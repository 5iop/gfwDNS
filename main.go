package main

import (
	"flag"
	"gfwDNS/domaintrie"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// 命令行参数
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	configFile := flag.String("config", "config.yaml", "Path to configuration file")
	flag.Parse()

	// 加载配置文件
	config, err := LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// 创建白名单
	whitelist, err := domaintrie.NewDomainTrie(
		config.Whitelist.File,
		config.Whitelist.TLD,
	)
	if err != nil {
		log.Fatalf("Failed to create whitelist: %v", err)
	}

	// 创建DNS服务器
	server, err := NewDNSServer(
		config.Server.Listen,
		config.Upstream.DNS.Address,
		config.Upstream.DNS.Port,
		whitelist,
		config.ConvertToDoHServers(),
	)
	if err != nil {
		log.Fatalf("Failed to create DNS server: %v", err)
	}

	// 设置优雅退出
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 启动服务器
	log.Printf("Starting DNS server on %s", config.Server.Listen)
	log.Printf("Using upstream DNS server: %s:%d",
		config.Upstream.DNS.Address,
		config.Upstream.DNS.Port,
	)

	// 在goroutine中启动服务器
	errChan := make(chan error, 1)
	go func() {
		if err := server.Start(); err != nil {
			errChan <- err
		}
	}()

	// 等待信号
	select {
	case err := <-errChan:
		log.Fatalf("DNS server error: %v", err)
	case sig := <-sigChan:
		log.Printf("Received signal %v, shutting down", sig)
		if err := server.Stop(); err != nil {
			log.Printf("Error stopping server: %v", err)
		}
		log.Println("Server stopped successfully")
	}
}
