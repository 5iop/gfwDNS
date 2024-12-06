package dnsdb

import (
	"container/list"
	"database/sql"
	"sync"
	"time"

	_ "github.com/glebarez/go-sqlite"
)

const (
	defaultTTL = 86400 * 30 // defaultTTL 是默认的TTL值，当记录没有TTL时使用此值
	maxTTL     = 86400 * 30 // maxTTL 是允许的最大TTL值，超过此值会被截断，这可以防止TTL设置过长导致记录长期占用内存
)

// DNSRecord 表示一条DNS记录
type DNSRecord struct {
	Domain    string
	Type      string
	Value     string
	TTL       int64
	ExpiresAt int64
}

// LRUCache 实现LRU缓存
type LRUCache struct {
	capacity int
	cache    map[string]*list.Element
	list     *list.List
	mu       sync.RWMutex
}

type cacheItem struct {
	key       string
	frequency int
}

// DNSDB 主数据库结构体
type DNSDB struct {
	db         *sql.DB
	cache      *LRUCache
	notifyChan chan DNSRecord
	done       chan struct{}
	mu         sync.RWMutex
}

// NewDNSDB 创建新的DNS数据库实例
func NewDNSDB(notifyChan chan DNSRecord) (*DNSDB, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}

	// 创建DNS记录表
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS dns_records (
			domain TEXT,
			type TEXT,
			value TEXT,
			ttl INTEGER,
			expires_at INTEGER,
			PRIMARY KEY (domain, type, value)
		)
	`)
	if err != nil {
		return nil, err
	}

	dnsDB := &DNSDB{
		db:         db,
		cache:      newLRUCache(10000),
		notifyChan: notifyChan,
		done:       make(chan struct{}),
	}

	// 启动TTL检查goroutine
	go dnsDB.checkExpiredRecords()

	return dnsDB, nil
}

// AddRecord 只添加记录到数据库
func (db *DNSDB) AddRecord(record DNSRecord) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	// 处理TTL
	if record.TTL <= 0 {
		record.TTL = defaultTTL
	} else if record.TTL > maxTTL {
		record.TTL = maxTTL
	}

	now := time.Now().Unix()
	record.ExpiresAt = now + record.TTL

	// 只更新数据库记录
	_, err := db.db.Exec(`
        INSERT OR REPLACE INTO dns_records (domain, type, value, ttl, expires_at)
        VALUES (?, ?, ?, ?, ?)
    `, record.Domain, record.Type, record.Value, record.TTL, record.ExpiresAt)

	return err
}

// UpdateCache 只更新缓存
func (db *DNSDB) UpdateCache(domain, recordType string) {
	cacheKey := domain + ":" + recordType
	db.cache.Add(cacheKey)
}

// GetRecords 获取域名的DNS记录
func (db *DNSDB) GetRecords(domain, recordType string) ([]DNSRecord, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	// 只在查询时更新缓存
	db.UpdateCache(domain, recordType)

	rows, err := db.db.Query(`
        SELECT domain, type, value, ttl, expires_at
        FROM dns_records
        WHERE domain = ? AND type = ? AND expires_at > ?
    `, domain, recordType, time.Now().Unix())

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []DNSRecord
	for rows.Next() {
		var record DNSRecord
		err := rows.Scan(&record.Domain, &record.Type, &record.Value, &record.TTL, &record.ExpiresAt)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}

	return records, nil
}

// Close 关闭数据库连接
func (db *DNSDB) Close() error {
	close(db.done)
	return db.db.Close()
}

// checkExpiredRecords 检查过期记录
func (db *DNSDB) checkExpiredRecords() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			db.mu.Lock()
			now := time.Now().Unix()
			rows, err := db.db.Query(`
				SELECT domain, type, value, ttl, expires_at
				FROM dns_records
				WHERE expires_at <= ?
			`, now)

			if err != nil {
				db.mu.Unlock()
				continue
			}

			var expiredRecords []DNSRecord
			for rows.Next() {
				var record DNSRecord
				err := rows.Scan(&record.Domain, &record.Type, &record.Value, &record.TTL, &record.ExpiresAt)
				if err != nil {
					continue
				}
				expiredRecords = append(expiredRecords, record)
			}
			rows.Close()

			// 处理过期记录
			for _, record := range expiredRecords {
				cacheKey := record.Domain + ":" + record.Type
				if db.cache.Contains(cacheKey) {
					// 如果在缓存中，发送通知
					select {
					case db.notifyChan <- record:
					default:
						// 通道已满，跳过通知
					}
				}

				// 删除过期记录
				_, err := db.db.Exec(`
					DELETE FROM dns_records
					WHERE domain = ? AND type = ? AND value = ?
				`, record.Domain, record.Type, record.Value)
				if err != nil {
					continue
				}
			}
			db.mu.Unlock()

		case <-db.done:
			return
		}
	}
}

// newLRUCache 创建新的LRU缓存
func newLRUCache(capacity int) *LRUCache {
	return &LRUCache{
		capacity: capacity,
		cache:    make(map[string]*list.Element),
		list:     list.New(),
	}
}

// Add 添加或更新缓存项
func (c *LRUCache) Add(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if element, exists := c.cache[key]; exists {
		c.list.MoveToFront(element)
		item := element.Value.(*cacheItem)
		item.frequency++
		return
	}

	if c.list.Len() >= c.capacity {
		// 移除最少使用的项
		element := c.list.Back()
		if element != nil {
			item := element.Value.(*cacheItem)
			delete(c.cache, item.key)
			c.list.Remove(element)
		}
	}

	// 添加新项
	element := c.list.PushFront(&cacheItem{
		key:       key,
		frequency: 1,
	})
	c.cache[key] = element
}

// Contains 检查键是否在缓存中
func (c *LRUCache) Contains(key string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, exists := c.cache[key]
	return exists
}
