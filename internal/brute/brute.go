package brute

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/subsll/subsoil/internal/dnsx"
	"github.com/subsll/subsoil/internal/model"

	"github.com/miekg/dns"
)

// Options controls a brute-force run.
type Options struct {
	Workers    int
	IPv6       bool
	Wildcard   model.Wildcard
	Progress   func(done, total, hits int)
	RetryLimit int
}

// Result is the outcome of brute forcing one domain.
type Result struct {
	Hosts         []model.Host
	Tried         int
	Hits          int
	WildcardDrops int
	Errors        int
}

// Run resolves each label under domain with a bounded worker pool.
func Run(ctx context.Context, r *dnsx.Resolver, domain string, words []string, opt Options) Result {
	if opt.Workers <= 0 {
		opt.Workers = 16
	}
	if opt.Workers > len(words) && len(words) > 0 {
		opt.Workers = len(words)
	}

	jobs := make(chan string)
	var (
		wg           sync.WaitGroup
		mu           sync.Mutex
		res          Result
		attempted    atomic.Int64
		hits         atomic.Int64
		lastProgress atomic.Int64
		hosts        []model.Host
	)

	workers := opt.Workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for label := range jobs {
				n := attempted.Add(1)
				if opt.Progress != nil && n%100 == 0 {
					lastProgress.Store(n)
					opt.Progress(int(n), len(words), int(hits.Load()))
				}
				qname := label + "." + domain
				rrs, rcode, err := r.Lookup(ctx, qname, dns.TypeA)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					mu.Lock()
					res.Errors++
					mu.Unlock()
					continue
				}
				if rcode != dns.RcodeSuccess {
					continue
				}
				ips := dnsx.IPs(rrs)
				cnames := dnsx.CNAMEs(rrs)
				if len(ips) == 0 && len(cnames) == 0 {
					continue
				}
				if dnsx.WildcardMatch(opt.Wildcard, ips, cnames) {
					mu.Lock()
					res.WildcardDrops++
					mu.Unlock()
					continue
				}

				h := model.Host{Name: qname, CNAME: first(cnames), Sources: []string{"brute"}, FirstSeen: time.Now().UTC()}
				for _, ip := range ips {
					if isV6(ip) {
						h.AAAA = append(h.AAAA, ip)
					} else {
						h.IPs = append(h.IPs, ip)
					}
				}
				if opt.IPv6 {
					if extra, _, err := r.Lookup(ctx, qname, dns.TypeAAAA); err == nil {
						for _, ip := range dnsx.IPs(extra) {
							if isV6(ip) && !contains(h.AAAA, ip) {
								h.AAAA = append(h.AAAA, ip)
							}
						}
					}
				}

				mu.Lock()
				hosts = append(hosts, h)
				mu.Unlock()
				hits.Add(1)
			}
		}()
	}

	for _, w := range words {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			res.Tried = int(attempted.Load())
			res.Hits = len(hosts)
			return finish(res, hosts)
		case jobs <- w:
		}
	}
	close(jobs)
	wg.Wait()
	res.Tried = int(attempted.Load())
	res.Hits = len(hosts)
	if opt.Progress != nil && lastProgress.Load() != int64(res.Tried) {
		opt.Progress(res.Tried, len(words), res.Hits)
	}
	return finish(res, hosts)
}

func finish(res Result, hosts []model.Host) Result {
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })
	res.Hosts = hosts
	res.Hits = len(hosts)
	return res
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

func isV6(ip string) bool {
	for i := 0; i < len(ip); i++ {
		if ip[i] == ':' {
			return true
		}
	}
	return false
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
