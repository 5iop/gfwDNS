package main

import (
	"fmt"
	"gfwDNS/dnsdb"
	"gfwDNS/domaintrie"
	"gfwDNS/upstream"
	"github.com/miekg/dns"
	"log"
	"net"
	"strconv"
	"strings"
)

type DNSServer struct {
	db            *dnsdb.DNSDB
	server        *dns.Server
	upstreamAddr  string
	upstreamPort  int
	notifyChan    chan dnsdb.DNSRecord
	supportedType map[uint16]string
	whitelist     *domaintrie.DomainTrie
	up            *upstream.Upstream
}

// NewDNSServer 创建新的DNS服务器实例
func NewDNSServer(addr string, upstreamAddr string, upstreamPort int, whitelist *domaintrie.DomainTrie, outside []upstream.DoHServer) (*DNSServer, error) {
	notifyChan := make(chan dnsdb.DNSRecord, 1000)
	db, err := dnsdb.NewDNSDB(notifyChan)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNSDB: %v", err)
	}
	// 创建上游处理器
	up, err := upstream.NewUpstream(outside, db, notifyChan)
	if err != nil {
		log.Fatal(err)
	}

	server := &DNSServer{
		db:           db,
		upstreamAddr: upstreamAddr,
		upstreamPort: upstreamPort,
		notifyChan:   notifyChan,
		whitelist:    whitelist,
		up:           up,
		supportedType: map[uint16]string{
			dns.TypeA:          "A",
			dns.TypeNS:         "NS",
			dns.TypeMD:         "MD",
			dns.TypeMF:         "MF",
			dns.TypeCNAME:      "CNAME",
			dns.TypeSOA:        "SOA",
			dns.TypeMB:         "MB",
			dns.TypeMG:         "MG",
			dns.TypeMR:         "MR",
			dns.TypeNULL:       "NULL",
			dns.TypePTR:        "PTR",
			dns.TypeHINFO:      "HINFO",
			dns.TypeMINFO:      "MINFO",
			dns.TypeMX:         "MX",
			dns.TypeTXT:        "TXT",
			dns.TypeRP:         "RP",
			dns.TypeAFSDB:      "AFSDB",
			dns.TypeX25:        "X25",
			dns.TypeISDN:       "ISDN",
			dns.TypeRT:         "RT",
			dns.TypeNSAPPTR:    "NSAPPTR",
			dns.TypeSIG:        "SIG",
			dns.TypeKEY:        "KEY",
			dns.TypePX:         "PX",
			dns.TypeGPOS:       "GPOS",
			dns.TypeAAAA:       "AAAA",
			dns.TypeLOC:        "LOC",
			dns.TypeNXT:        "NXT",
			dns.TypeEID:        "EID",
			dns.TypeNIMLOC:     "NIMLOC",
			dns.TypeSRV:        "SRV",
			dns.TypeATMA:       "ATMA",
			dns.TypeNAPTR:      "NAPTR",
			dns.TypeKX:         "KX",
			dns.TypeCERT:       "CERT",
			dns.TypeDNAME:      "DNAME",
			dns.TypeOPT:        "OPT",
			dns.TypeAPL:        "APL",
			dns.TypeDS:         "DS",
			dns.TypeSSHFP:      "SSHFP",
			dns.TypeIPSECKEY:   "IPSECKEY",
			dns.TypeRRSIG:      "RRSIG",
			dns.TypeNSEC:       "NSEC",
			dns.TypeDNSKEY:     "DNSKEY",
			dns.TypeDHCID:      "DHCID",
			dns.TypeNSEC3:      "NSEC3",
			dns.TypeNSEC3PARAM: "NSEC3PARAM",
			dns.TypeTLSA:       "TLSA",
			dns.TypeSMIMEA:     "SMIMEA",
			dns.TypeHIP:        "HIP",
			dns.TypeNINFO:      "NINFO",
			dns.TypeRKEY:       "RKEY",
			dns.TypeTALINK:     "TALINK",
			dns.TypeCDS:        "CDS",
			dns.TypeCDNSKEY:    "CDNSKEY",
			dns.TypeOPENPGPKEY: "OPENPGPKEY",
			dns.TypeCSYNC:      "CSYNC",
			dns.TypeZONEMD:     "ZONEMD",
			dns.TypeSVCB:       "SVCB",
			dns.TypeHTTPS:      "HTTPS",
			dns.TypeSPF:        "SPF",
			dns.TypeUINFO:      "UINFO",
			dns.TypeUID:        "UID",
			dns.TypeGID:        "GID",
			dns.TypeUNSPEC:     "UNSPEC",
			dns.TypeNID:        "NID",
			dns.TypeL32:        "L32",
			dns.TypeL64:        "L64",
			dns.TypeLP:         "LP",
			dns.TypeEUI48:      "EUI48",
			dns.TypeEUI64:      "EUI64",
			dns.TypeURI:        "URI",
			dns.TypeCAA:        "CAA",
			dns.TypeAVC:        "AVC",
			dns.TypeAMTRELAY:   "AMTRELAY",
			dns.TypeTKEY:       "TKEY",
			dns.TypeTSIG:       "TSIG",
			dns.TypeIXFR:       "IXFR",
			dns.TypeAXFR:       "AXFR",
			dns.TypeMAILB:      "MAILB",
			dns.TypeMAILA:      "MAILA",
			dns.TypeANY:        "ANY",
			dns.TypeTA:         "TA",
			dns.TypeDLV:        "DLV",
		},
	}

	// 创建DNS服务器
	server.server = &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: dns.HandlerFunc(server.handleDNSRequest),
	}

	// 启动过期记录通知处理
	//go server.handleExpiredRecords()

	return server, nil
}

// Start 启动DNS服务器
func (s *DNSServer) Start() error {
	return s.server.ListenAndServe()
}

// Stop 停止DNS服务器
func (s *DNSServer) Stop() error {
	if err := s.server.Shutdown(); err != nil {
		return err
	}
	s.up.Close()
	return s.db.Close()
}

// handleDNSRequest 处理DNS请求
func (s *DNSServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	// 处理每个问题
	for _, q := range r.Question {
		// 检查是否支持该记录类型
		recordType, supported := s.supportedType[q.Qtype]
		if !supported {
			log.Printf("Unsupported record type: %d", q.Qtype)
			continue
		}

		// 格式化域名（移除末尾的点）
		domain := strings.TrimSuffix(q.Name, ".")

		// 检查域名是否在白名单中
		isWhitelisted, err := s.whitelist.Match(domain)
		if err != nil {
			log.Printf("Error checking whitelist for domain %s: %v", domain, err)
		}

		if isWhitelisted {
			// 如果在白名单中，直接使用上游服务器
			upstreamRecords, err := s.queryUpstream(r)
			if err != nil {
				log.Printf("Error querying upstream for whitelisted domain: %v", err)
				continue
			}

			// 添加上游响应到回复消息
			m.Answer = append(m.Answer, s.convertToRR(upstreamRecords)...)
			log.Printf("Whitelisted domain %s, using upstream directly", domain)
			continue
		}

		// 记录缓存
		s.db.UpdateCache(domain, recordType)
		// 从本地数据库查询记录
		records, err := s.db.GetRecords(domain, recordType)
		if err != nil {
			log.Printf("Error querying local database: %v", err)
			continue
		}

		// 如果本地没有记录，从上游服务器查询
		if len(records) == 0 {
			upstreamRecords, err := s.up.QueryUpstream(r)
			if err != nil {
				log.Printf("Error querying upstream: %v", err)
				continue
			}

			// 将上游记录存入本地数据库
			for _, record := range upstreamRecords {
				if err := s.db.AddRecord(record); err != nil {
					log.Printf("Error storing record: %v", err)
				}
			}

			// 添加上游响应到回复消息
			m.Answer = append(m.Answer, s.convertToRR(upstreamRecords)...)
		} else {
			// 使用本地记录
			m.Answer = append(m.Answer, s.convertToRR(records)...)
			log.Printf("Found %d local records for %v", len(records), s.convertToRR(records))
		}
	}
	log.Printf("Replying with %v", m.Answer)
	if err := w.WriteMsg(m); err != nil {
		log.Println(err)
		return
	}
}

// queryUpstream 从上游DNS服务器查询
func (s *DNSServer) queryUpstream(r *dns.Msg) ([]dnsdb.DNSRecord, error) {
	c := new(dns.Client)
	upstreamAddr := fmt.Sprintf("%s:%d", s.upstreamAddr, s.upstreamPort)
	resp, _, err := c.Exchange(r, upstreamAddr)
	if err != nil {
		return nil, err
	}

	var records []dnsdb.DNSRecord
	for _, ans := range resp.Answer {
		record := s.convertFromRR(ans)
		if record != nil {
			records = append(records, *record)
		}
	}

	return records, nil
}

// convertFromRR 将DNS记录转换为内部记录格式
func (s *DNSServer) convertFromRR(rr dns.RR) *dnsdb.DNSRecord {
	header := rr.Header()
	recordType, supported := s.supportedType[header.Rrtype]
	if !supported {
		return nil
	}

	record := &dnsdb.DNSRecord{
		Domain: strings.TrimSuffix(header.Name, "."),
		Type:   recordType,
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
		// 对于其他类型，使用默认字符串表示
		record.Value = strings.TrimPrefix(rr.String(), header.String())
	}

	return record
}

// convertToRR 中的修改部分
func (s *DNSServer) convertToRR(records []dnsdb.DNSRecord) []dns.RR {
	var rrs []dns.RR
	for _, record := range records {
		var rr dns.RR
		var err error

		switch record.Type {
		case "A":
			header := dns.RR_Header{
				Name:   record.Domain + ".",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    uint32(record.TTL),
			}
			rr = &dns.A{
				Hdr: header,
				A:   net.ParseIP(record.Value),
			}
		case "AAAA":
			header := dns.RR_Header{
				Name:   record.Domain + ".",
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    uint32(record.TTL),
			}
			rr = &dns.AAAA{
				Hdr:  header,
				AAAA: net.ParseIP(record.Value),
			}
		case "CNAME":
			header := dns.RR_Header{
				Name:   record.Domain + ".",
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    uint32(record.TTL),
			}
			rr = &dns.CNAME{
				Hdr:    header,
				Target: record.Value,
			}
		case "NS":
			header := dns.RR_Header{
				Name:   record.Domain + ".",
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    uint32(record.TTL),
			}
			rr = &dns.NS{
				Hdr: header,
				Ns:  record.Value,
			}
		case "PTR":
			header := dns.RR_Header{
				Name:   record.Domain + ".",
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    uint32(record.TTL),
			}
			rr = &dns.PTR{
				Hdr: header,
				Ptr: record.Value,
			}
		case "MX":
			parts := strings.Fields(record.Value)
			if len(parts) == 2 {
				pref, _ := strconv.Atoi(parts[0])
				header := dns.RR_Header{
					Name:   record.Domain + ".",
					Rrtype: dns.TypeMX,
					Class:  dns.ClassINET,
					Ttl:    uint32(record.TTL),
				}
				rr = &dns.MX{
					Hdr:        header,
					Preference: uint16(pref),
					Mx:         parts[1],
				}
			}
		case "TXT":
			header := dns.RR_Header{
				Name:   record.Domain + ".",
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    uint32(record.TTL),
			}
			rr = &dns.TXT{
				Hdr: header,
				Txt: []string{record.Value},
			}
		case "SRV":
			parts := strings.Fields(record.Value)
			if len(parts) == 4 {
				priority, _ := strconv.Atoi(parts[0])
				weight, _ := strconv.Atoi(parts[1])
				port, _ := strconv.Atoi(parts[2])
				header := dns.RR_Header{
					Name:   record.Domain + ".",
					Rrtype: dns.TypeSRV,
					Class:  dns.ClassINET,
					Ttl:    uint32(record.TTL),
				}
				rr = &dns.SRV{
					Hdr:      header,
					Priority: uint16(priority),
					Weight:   uint16(weight),
					Port:     uint16(port),
					Target:   parts[3],
				}
			}
		default:
			rr, err = dns.NewRR(fmt.Sprintf("%s %d IN %s %s",
				record.Domain+".", record.TTL, record.Type, record.Value))
			if err != nil {
				log.Printf("Error creating RR: %v", err)
				continue
			}
		}

		if rr != nil {
			rrs = append(rrs, rr)
		}
	}

	return rrs
}

// handleExpiredRecords 处理过期记录通知
func (s *DNSServer) handleExpiredRecords() {
	for record := range s.notifyChan {
		log.Printf("Record expired: %+v", record)
		// 这里可以添加自定义的过期处理逻辑
	}
}
