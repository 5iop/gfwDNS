package domaintrie

import (
	"bufio"
	"golang.org/x/net/idna"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// TrieNode 表示字典树节点
type TrieNode struct {
	children map[string]*TrieNode
	isEnd    bool
}

// DomainTrie 表示域名字典树
type DomainTrie struct {
	root     *TrieNode
	mu       sync.RWMutex // 将锁移动到 DomainTrie 结构体级别
	filePath string
	tlds     []string
	done     chan struct{}
}

// NewTrieNode 创建新的字典树节点
func NewTrieNode() *TrieNode {
	return &TrieNode{
		children: make(map[string]*TrieNode),
		isEnd:    false,
	}
}

// NewDomainTrie 创建新的域名字典树
func NewDomainTrie(filePath string, tlds []string) (*DomainTrie, error) {
	trie := &DomainTrie{
		root:     NewTrieNode(),
		filePath: filePath,
		done:     make(chan struct{}),
		tlds:     tlds,
	}

	// 加载域名列表
	if err := trie.loadDomains(); err != nil {
		return nil, err
	}

	// 启动定期更新协程
	go trie.periodicUpdate()

	return trie, nil
}

// Close 关闭字典树，停止定期更新
func (t *DomainTrie) Close() {
	close(t.done)
}

// insertNode 向特定节点插入域名
func (t *DomainTrie) insertNode(node *TrieNode, parts []string) {
	current := node
	for _, part := range parts {
		if part == "" {
			continue
		}
		if _, exists := current.children[part]; !exists {
			current.children[part] = NewTrieNode()
		}
		current = current.children[part]
	}
	current.isEnd = true
}

// Insert 插入域名到字典树
func (t *DomainTrie) Insert(domain string) error {
	// 处理非ASCII域名
	asciiDomain, err := idna.ToASCII(domain)
	if err != nil {
		return err
	}

	// 将域名分割并反转
	parts := strings.Split(strings.TrimSpace(strings.ToLower(asciiDomain)), ".")
	reverseSlice(parts)

	t.mu.Lock()
	t.insertNode(t.root, parts)
	t.mu.Unlock()
	return nil
}

// Match 修改匹配逻辑，确保可以匹配到TLD
func (t *DomainTrie) Match(domain string) (bool, error) {
	// 处理非ASCII域名
	asciiDomain, err := idna.ToASCII(domain)
	if err != nil {
		return false, err
	}

	// 将域名分割并反转
	parts := strings.Split(strings.TrimSpace(strings.ToLower(asciiDomain)), ".")
	reverseSlice(parts)

	t.mu.RLock()
	defer t.mu.RUnlock()

	current := t.root
	matched := false

	// 遍历所有部分，检查每个层级是否匹配
	for i := 0; i < len(parts); i++ {
		if current.isEnd {
			matched = true
			break
		}

		next, exists := current.children[parts[i]]
		if !exists {
			break
		}
		current = next
	}

	// 检查最后一个节点
	if !matched {
		matched = current.isEnd
	}

	return matched, nil
}

// loadDomains 修改加载逻辑，确保TLD正确加载
func (t *DomainTrie) loadDomains() error {
	// 创建新的根节点
	newRoot := NewTrieNode()

	// 首先加入顶级域名
	for _, tld := range t.tlds {
		tld = strings.TrimPrefix(tld, ".")
		tld = strings.ToLower(tld)
		parts := []string{tld}
		t.insertNode(newRoot, parts)
	}

	// 然后加载文件中的域名
	file, err := os.Open(t.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := scanner.Text()
		parts := strings.Split(strings.TrimSpace(strings.ToLower(domain)), ".")
		reverseSlice(parts)
		t.insertNode(newRoot, parts)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	// 原子地替换根节点
	t.mu.Lock()
	t.root = newRoot
	t.mu.Unlock()

	return nil
}

// periodicUpdate 定期更新域名列表
func (t *DomainTrie) periodicUpdate() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := t.loadDomains(); err != nil {
				log.Printf("Error updating domain list: %v", err)
			}
		case <-t.done:
			return
		}
	}
}

// reverseSlice 反转切片
func reverseSlice(s []string) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
