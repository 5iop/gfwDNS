package main

import (
	"fmt"
	"gfwDNS/upstream"
	"gopkg.in/yaml.v3"
	"os"
)

type Config struct {
	Server struct {
		Listen string `yaml:"listen"`
	} `yaml:"server"`

	Upstream struct {
		DNS struct {
			Address string `yaml:"address"`
			Port    int    `yaml:"port"`
		} `yaml:"dns"`
		DoH []struct {
			URL      string `yaml:"url"`
			Proxy    string `yaml:"proxy"`
			Priority int    `yaml:"priority"`
		} `yaml:"doh"`
	} `yaml:"upstream"`

	Whitelist struct {
		File string   `yaml:"file"`
		TLD  []string `yaml:"tld"`
	} `yaml:"whitelist"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %v", err)
	}

	config := &Config{}
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("error parsing config file: %v", err)
	}

	return config, nil
}

// ConvertToDoHServers 将配置转换为 DoHServer 切片
func (c *Config) ConvertToDoHServers() []upstream.DoHServer {
	servers := make([]upstream.DoHServer, len(c.Upstream.DoH))
	for i, doh := range c.Upstream.DoH {
		servers[i] = upstream.DoHServer{
			URL:      doh.URL,
			Proxy:    doh.Proxy,
			Priority: doh.Priority,
		}
	}
	return servers
}
