package dnsx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/subsll/subsoil/internal/model"

	"github.com/miekg/dns"
)

// DetectWildcard probes for wildcard DNS by resolving random labels under the
// domain. Any answer to a random label means a wildcard is in play; the union
// of the observed addresses becomes the fingerprint used to filter brute-force
// false positives.
func DetectWildcard(ctx context.Context, r *Resolver, domain string, probes int) (model.Wildcard, error) {
	w := model.Wildcard{}
	if probes <= 0 {
		probes = 3
	}
	ipSet := make(map[string]struct{})
	cnameSet := make(map[string]struct{})
	var lastErr error

	for i := 0; i < probes; i++ {
		label, err := randomLabel()
		if err != nil {
			return w, err
		}
		qname := label + "." + domain
		rrs, _, err := r.Lookup(ctx, qname, dns.TypeA)
		if err != nil {
			lastErr = err
			continue
		}
		w.Probes = append(w.Probes, qname)
		for _, ip := range IPs(rrs) {
			ipSet[ip] = struct{}{}
		}
		for _, cn := range CNAMEs(rrs) {
			cnameSet[cn] = struct{}{}
		}
	}

	if len(ipSet) == 0 && len(cnameSet) == 0 {
		if lastErr != nil {
			return w, lastErr
		}
		return w, nil
	}
	w.Enabled = true
	w.IPs = sortedKeys(ipSet)
	w.CNAMEs = sortedKeys(cnameSet)
	return w, nil
}

// WildcardMatch reports whether an answer looks like the wildcard fingerprint.
func WildcardMatch(w model.Wildcard, ips, cnames []string) bool {
	if !w.Enabled {
		return false
	}
	if len(cnames) > 0 {
		for _, cn := range cnames {
			for _, wc := range w.CNAMEs {
				if cn == wc {
					return true
				}
			}
		}
	}
	if len(ips) == 0 {
		return false
	}
	if len(w.IPs) == 0 {
		// CNAME wildcard whose target has no A records.
		return len(cnames) > 0
	}
	for _, ip := range ips {
		found := false
		for _, wip := range w.IPs {
			if ip == wip {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func randomLabel() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "subsoil-" + hex.EncodeToString(b), nil
}

// ParseName normalises a DNS name: lowercase, no trailing dot, IDN rejected.
func ParseName(name string) (string, error) {
	name = strings.TrimSpace(strings.ToLower(name))
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return "", fmt.Errorf("empty domain")
	}
	if len(name) > 253 {
		return "", fmt.Errorf("domain %q is longer than 253 bytes", name)
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("domain %q needs at least two labels", name)
	}
	for _, l := range labels {
		if !validLabel(l) {
			return "", fmt.Errorf("domain %q has an invalid label %q", name, l)
		}
	}
	if tld := labels[len(labels)-1]; len(tld) < 2 {
		return "", fmt.Errorf("domain %q has an invalid TLD %q", name, tld)
	}
	return name, nil
}

func validLabel(l string) bool {
	if len(l) == 0 || len(l) > 63 {
		return false
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return false
	}
	return true
}
