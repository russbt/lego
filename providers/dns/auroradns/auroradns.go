// Package auroradns implements a DNS provider for solving the DNS-01 challenge using Aurora DNS.
package auroradns

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ldez/go-auroradns"
	"github.com/xenolf/lego/old/acme"
	"github.com/xenolf/lego/platform/config/env"
)

const defaultBaseURL = "https://api.auroradns.eu"

// Config is used to configure the creation of the DNSProvider
type Config struct {
	BaseURL            string
	UserID             string
	Key                string
	PropagationTimeout time.Duration
	PollingInterval    time.Duration
	TTL                int
}

// NewDefaultConfig returns a default configuration for the DNSProvider
func NewDefaultConfig() *Config {
	return &Config{
		TTL:                env.GetOrDefaultInt("AURORA_TTL", 300),
		PropagationTimeout: env.GetOrDefaultSecond("AURORA_PROPAGATION_TIMEOUT", acme.DefaultPropagationTimeout),
		PollingInterval:    env.GetOrDefaultSecond("AURORA_POLLING_INTERVAL", acme.DefaultPollingInterval),
	}
}

// DNSProvider describes a provider for AuroraDNS
type DNSProvider struct {
	recordIDs   map[string]string
	recordIDsMu sync.Mutex
	config      *Config
	client      *auroradns.Client
}

// NewDNSProvider returns a DNSProvider instance configured for AuroraDNS.
// Credentials must be passed in the environment variables:
// AURORA_USER_ID and AURORA_KEY.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get("AURORA_USER_ID", "AURORA_KEY")
	if err != nil {
		return nil, fmt.Errorf("aurora: %v", err)
	}

	config := NewDefaultConfig()
	config.BaseURL = env.GetOrFile("AURORA_ENDPOINT")
	config.UserID = values["AURORA_USER_ID"]
	config.Key = values["AURORA_KEY"]

	return NewDNSProviderConfig(config)
}

// NewDNSProviderCredentials uses the supplied credentials
// to return a DNSProvider instance configured for AuroraDNS.
// Deprecated
func NewDNSProviderCredentials(baseURL string, userID string, key string) (*DNSProvider, error) {
	config := NewDefaultConfig()
	config.BaseURL = baseURL
	config.UserID = userID
	config.Key = key

	return NewDNSProviderConfig(config)
}

// NewDNSProviderConfig return a DNSProvider instance configured for AuroraDNS.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("aurora: the configuration of the DNS provider is nil")
	}

	if config.UserID == "" || config.Key == "" {
		return nil, errors.New("aurora: some credentials information are missing")
	}

	if config.BaseURL == "" {
		config.BaseURL = defaultBaseURL
	}

	tr, err := auroradns.NewTokenTransport(config.UserID, config.Key)
	if err != nil {
		return nil, fmt.Errorf("aurora: %v", err)
	}

	client, err := auroradns.NewClient(tr.Client(), auroradns.WithBaseURL(config.BaseURL))
	if err != nil {
		return nil, fmt.Errorf("aurora: %v", err)
	}

	return &DNSProvider{
		config:    config,
		client:    client,
		recordIDs: make(map[string]string),
	}, nil
}

// Present creates a record with a secret
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	fqdn, value, _ := acme.DNS01Record(domain, keyAuth)

	authZone, err := acme.FindZoneByFqdn(acme.ToFqdn(domain), acme.RecursiveNameservers)
	if err != nil {
		return fmt.Errorf("aurora: could not determine zone for domain: '%s'. %s", domain, err)
	}

	// 1. Aurora will happily create the TXT record when it is provided a fqdn,
	//    but it will only appear in the control panel and will not be
	//    propagated to DNS servers. Extract and use subdomain instead.
	// 2. A trailing dot in the fqdn will cause Aurora to add a trailing dot to
	//    the subdomain, resulting in _acme-challenge..<domain> rather
	//    than _acme-challenge.<domain>

	subdomain := fqdn[0 : len(fqdn)-len(authZone)-1]

	authZone = acme.UnFqdn(authZone)

	zone, err := d.getZoneInformationByName(authZone)
	if err != nil {
		return fmt.Errorf("aurora: could not create record: %v", err)
	}

	record := auroradns.Record{
		RecordType: "TXT",
		Name:       subdomain,
		Content:    value,
		TTL:        d.config.TTL,
	}

	newRecord, _, err := d.client.CreateRecord(zone.ID, record)
	if err != nil {
		return fmt.Errorf("aurora: could not create record: %v", err)
	}

	d.recordIDsMu.Lock()
	d.recordIDs[fqdn] = newRecord.ID
	d.recordIDsMu.Unlock()

	return nil
}

// CleanUp removes a given record that was generated by Present
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	fqdn, _, _ := acme.DNS01Record(domain, keyAuth)

	d.recordIDsMu.Lock()
	recordID, ok := d.recordIDs[fqdn]
	d.recordIDsMu.Unlock()

	if !ok {
		return fmt.Errorf("unknown recordID for %q", fqdn)
	}

	authZone, err := acme.FindZoneByFqdn(acme.ToFqdn(domain), acme.RecursiveNameservers)
	if err != nil {
		return fmt.Errorf("could not determine zone for domain: %q. %v", domain, err)
	}

	authZone = acme.UnFqdn(authZone)

	zone, err := d.getZoneInformationByName(authZone)
	if err != nil {
		return err
	}

	_, _, err = d.client.DeleteRecord(zone.ID, recordID)
	if err != nil {
		return err
	}

	d.recordIDsMu.Lock()
	delete(d.recordIDs, fqdn)
	d.recordIDsMu.Unlock()

	return nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

func (d *DNSProvider) getZoneInformationByName(name string) (auroradns.Zone, error) {
	zs, _, err := d.client.ListZones()
	if err != nil {
		return auroradns.Zone{}, err
	}

	for _, element := range zs {
		if element.Name == name {
			return element, nil
		}
	}

	return auroradns.Zone{}, fmt.Errorf("could not find Zone record")
}
