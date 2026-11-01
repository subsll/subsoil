// Package webx holds small HTTP helpers shared by the passive sources and the
// HTTP prober.
package webx

import (
	"crypto/tls"
	"math/rand/v2"
	"net"
	"net/http"
	"time"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
}

// RandomUA returns a browser User-Agent. The default Go agent is a very loud
// fingerprint, so every outbound request uses one of these instead.
func RandomUA() string {
	return userAgents[rand.IntN(len(userAgents))]
}

// NewClient builds a client with sensible recon defaults. Proxy settings are
// honoured from the environment.
func NewClient(timeout time.Duration, insecure bool) *http.Client {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // recon: self-signed certs are interesting
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
}
