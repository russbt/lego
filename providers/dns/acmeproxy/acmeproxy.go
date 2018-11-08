// Package acmeproxy implements a DNS provider for solving the DNS-01 challenge using acme-proxy.
package acmeproxy

import (
	"encoding/json"
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"time"
	"strings"

	"github.com/xenolf/lego/platform/config/env"
)

// Config is used to configure the creation of the DNSProvider
type Config struct {
	BaseURL            string
	Provider           string
	PropagationTimeout time.Duration
	PollingInterval    time.Duration
}

type Request struct {
	Domain   string `json:"domain"`
	Token    string `json:"token"`
	KeyAuth  string `json:"keyAuth'`
}

// NewDefaultConfig returns a default configuration for the DNSProvider
func NewDefaultConfig() *Config {
	return &Config{
		PropagationTimeout: env.GetOrDefaultSecond("ACMEPROXY_PROPAGATION_TIMEOUT", 10*time.Minute),
		PollingInterval:    env.GetOrDefaultSecond("ACMEPROXY_POLLING_INTERVAL", 10*time.Second),
	}
}

// DNSProvider describes a provider for acme-proxy
type DNSProvider struct {
	config *Config
}

// NewDNSProvider returns a DNSProvider instance configured for acme-proxy.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get("ACMEPROXY_BASEURL")
	if err != nil {
		return nil, fmt.Errorf("acmeproxy: %v", err)
	}

	config := NewDefaultConfig()
	config.BaseURL = strings.TrimSuffix(values["ACMEPROXY_BASEURL"], "/")
	if err != nil {
		return nil, fmt.Errorf("wrong port", err)
	}
	return NewDNSProviderConfig(config)
}

// NewDNSProviderConfig return a DNSProvider instance configured for acme-proxy.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("acmeproxy: the configuration of the DNS provider is nil")
	}

	return &DNSProvider{config: config}, nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

// Present creates a TXT record to fulfill the dns-01 challenge
func (d *DNSProvider) Present(domain, token, keyAuth string) error {

	req := Request{
		Domain:  domain,
		Token:   token,
		KeyAuth: keyAuth,
	}
	b := new (bytes.Buffer)
	json.NewEncoder(b).Encode(req)
	_, err := http.Post(d.config.BaseURL+"/present", "application/json", b)
	if err != nil {
		return fmt.Errorf("acmeproxy: error for %s in Present: %v", domain, err)
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {

	req := Request{
		Domain:  domain,
		Token:   token,
		KeyAuth: keyAuth,
	}
	b := new (bytes.Buffer)
	json.NewEncoder(b).Encode(req)
	_, err := http.Post(d.config.BaseURL+"/cleanup", "application/json", b)
	if err != nil {
		return fmt.Errorf("acmeproxy: error for %s in Present: %v", domain, err)
	}

	return nil
}
