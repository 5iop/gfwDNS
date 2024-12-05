package upstream

import (
	"encoding/base64"
	"fmt"
	"gfwDNS/dnsdb"
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
	"io"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

type DoHServer struct {
	URL      string
	Proxy    string
	Priority int
}

type Upstream struct {
	servers     []DoHServer
	db          *dnsdb.DNSDB
	notifyChan  chan dnsdb.DNSRecord
	done        chan struct{}
	mu          sync.RWMutex
	proxyDialer map[string]proxy.Dialer
}

func NewUpstream(servers []DoHServer, db *dnsdb.DNSDB, notifyChan chan dnsdb.DNSRecord) (*Upstream, error) {
	up := &Upstream{
		servers:     servers,
		db:          db,
		notifyChan:  notifyChan,
		done:        make(chan struct{}),
		proxyDialer: make(map[string]proxy.Dialer),
	}

	for _, server := range servers {
		if dialer, err := proxy.SOCKS5("tcp", server.Proxy, nil, proxy.Direct); err == nil {
			up.proxyDialer[server.Proxy] = dialer
		} else {
			return nil, fmt.Errorf("failed to create SOCKS5 dialer for %s: %v", server.Proxy, err)
		}
	}

	go up.handleExpiredRecords()
	return up, nil
}

// QueryUpstream 实现与DNSServer.queryUpstream相同的接口
func (u *Upstream) QueryUpstream(r *dns.Msg) ([]dnsdb.DNSRecord, error) {
	type queryResult struct {
		records []dnsdb.DNSRecord
		err     error
	}

	// 使用带缓冲的channel来接收所有查询结果
	resultChan := make(chan queryResult, len(u.servers))
	// 为每个服务器启动一个goroutine进行查询
	for _, server := range u.servers {
		go func(server DoHServer) {
			// 构建DoH请求
			req, err := u.createDoHRequest(&server, r)
			if err != nil {
				resultChan <- queryResult{nil, err}
				return
			}

			// 创建带超时的客户端
			client := &http.Client{
				Transport: &http.Transport{
					Dial: u.proxyDialer[server.Proxy].Dial,
				},
				Timeout: 5 * time.Second, // 设置较短的超时时间以快速失败
			}

			// 发送请求
			resp, err := client.Do(req)
			if err != nil {
				resultChan <- queryResult{nil, err}
				return
			}
			defer resp.Body.Close()

			// 检查响应状态码
			if resp.StatusCode != http.StatusOK {
				resultChan <- queryResult{nil, fmt.Errorf("server returned %d", resp.StatusCode)}
				return
			}

			// 读取响应
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				resultChan <- queryResult{nil, err}
				return
			}

			// 解析DNS消息
			msg := new(dns.Msg)
			if err := msg.Unpack(body); err != nil {
				resultChan <- queryResult{nil, err}
				return
			}

			// 检查响应是否有效
			if msg.Rcode != dns.RcodeSuccess {
				resultChan <- queryResult{nil, fmt.Errorf("DNS query failed with code %d", msg.Rcode)}
				return
			}

			// 转换记录
			var records []dnsdb.DNSRecord
			for _, ans := range msg.Answer {
				record := u.convertFromRR(ans)
				if record != nil {
					records = append(records, *record)
				}
			}

			// 检查是否有有效记录
			if len(records) == 0 {
				resultChan <- queryResult{nil, fmt.Errorf("no valid records")}
				return
			}

			resultChan <- queryResult{records, nil}
		}(server)
	}

	// 等待第一个成功的响应或所有查询失败
	var lastErr error
	for i := 0; i < len(u.servers); i++ {
		result := <-resultChan
		if result.err == nil {
			log.Printf("Got successful response with %d records", len(result.records))
			return result.records, nil
		}
		lastErr = result.err
	}

	// 如果所有查询都失败，返回最后一个错误
	return nil, fmt.Errorf("all DoH queries failed, last error: %v", lastErr)
}

func (u *Upstream) createDoHRequest(server *DoHServer, r *dns.Msg) (*http.Request, error) {
	dnsQuery, err := r.Pack()
	if err != nil {
		return nil, err
	}

	b64Query := base64.RawURLEncoding.EncodeToString(dnsQuery)
	req, err := http.NewRequest("GET", fmt.Sprintf("%s?dns=%s", server.URL, b64Query), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/dns-message")
	return req, nil
}

func (u *Upstream) convertFromRR(rr dns.RR) *dnsdb.DNSRecord {
	header := rr.Header()
	record := &dnsdb.DNSRecord{
		Domain: strings.TrimSuffix(header.Name, "."),
		Type:   dns.TypeToString[header.Rrtype],
		TTL:    int64(header.Ttl),
	}

	switch v := rr.(type) {
	case *dns.A:
		record.Value = v.A.String()
	case *dns.AAAA:
		record.Value = v.AAAA.String()
	case *dns.CNAME:
		record.Value = v.Target
	case *dns.MX:
		record.Value = fmt.Sprintf("%d %s", v.Preference, v.Mx)
	case *dns.NS:
		record.Value = v.Ns
	case *dns.PTR:
		record.Value = v.Ptr
	case *dns.SOA:
		record.Value = fmt.Sprintf("%s %s %d %d %d %d %d",
			v.Ns, v.Mbox, v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)
	case *dns.TXT:
		record.Value = strings.Join(v.Txt, " ")
	case *dns.SRV:
		record.Value = fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, v.Target)
	case *dns.CAA:
		record.Value = fmt.Sprintf("%d %s \"%s\"", v.Flag, v.Tag, v.Value)
	case *dns.HINFO:
		record.Value = fmt.Sprintf("\"%s\" \"%s\"", v.Cpu, v.Os)
	case *dns.MINFO:
		record.Value = fmt.Sprintf("%s %s", v.Rmail, v.Email)
	case *dns.RP:
		record.Value = fmt.Sprintf("%s %s", v.Mbox, v.Txt)
	case *dns.NAPTR:
		record.Value = fmt.Sprintf("%d %d \"%s\" \"%s\" \"%s\" %s",
			v.Order, v.Preference, v.Flags, v.Service, v.Regexp, v.Replacement)
	case *dns.CERT:
		record.Value = fmt.Sprintf("%d %d %d %s", v.Type, v.KeyTag, v.Algorithm, v.Certificate)
	case *dns.DNAME:
		record.Value = v.Target
	case *dns.DS:
		record.Value = fmt.Sprintf("%d %d %d %s", v.KeyTag, v.Algorithm, v.DigestType, v.Digest)
	case *dns.SSHFP:
		record.Value = fmt.Sprintf("%d %d %s", v.Algorithm, v.Type, v.FingerPrint)
	case *dns.TLSA:
		record.Value = fmt.Sprintf("%d %d %d %s", v.Usage, v.Selector, v.MatchingType, v.Certificate)
	case *dns.URI:
		record.Value = fmt.Sprintf("%d %d %s", v.Priority, v.Weight, v.Target)
	case *dns.LOC:
		record.Value = fmt.Sprintf("%d %d %d %d %d %d %d",
			v.Version, v.Size, v.HorizPre, v.VertPre, v.Latitude, v.Longitude, v.Altitude)
	default:
		record.Value = strings.TrimPrefix(rr.String(), header.String())
	}

	return record
}

func (u *Upstream) handleExpiredRecords() {
	for {
		select {
		case record := <-u.notifyChan:
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(record.Domain), dns.StringToType[record.Type])
			m.RecursionDesired = true

			records, err := u.QueryUpstream(m)
			if err != nil {
				log.Printf("Error updating expired record for %s: %v", record.Domain, err)
				continue
			}

			for _, newRecord := range records {
				if err := u.db.AddRecord(newRecord); err != nil {
					log.Printf("Error storing updated record: %v", err)
				}
			}
		case <-u.done:
			return
		}
	}
}

func (u *Upstream) Close() {
	close(u.done)
}

func (u *Upstream) getRandomServer() *DoHServer {
	u.mu.RLock()
	defer u.mu.RUnlock()

	if len(u.servers) == 0 {
		return nil
	}
	return &u.servers[rand.Intn(len(u.servers))]
}
