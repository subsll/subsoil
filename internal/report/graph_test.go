package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/subsll/subsoil/internal/model"
)

func TestBuildGraphConnectsEntities(t *testing.T) {
	res, _ := fixture(t)
	now := time.Now().UTC()
	res.Records = append(res.Records,
		model.RecordSet{Name: "example.com", Type: "NS", RRs: []string{"example.com.\t0\tIN\tNS\tns1.example.com."}},
		model.RecordSet{Name: "example.com", Type: "MX", RRs: []string{"example.com.\t0\tIN\tMX\t10 mail.example.com."}},
	)
	res.Hosts = append(res.Hosts, model.Host{
		Name: "api.example.com", CNAME: "www.example.com", Sources: []string{"certspotter"},
		Resolved: true, FirstSeen: now, Hash: "cafebabe",
	})
	res.SRV = []model.SRV{{Name: "_sip._tcp.example.com", Target: "sip.example.com", Port: 5060}}
	res.PTR = []model.PTR{{IP: "192.0.2.1", Names: []string{"www.example.com"}}}
	res.HTTP = []model.HTTP{{
		Host: "www.example.com", Scheme: "https", Status: 200,
		TLS: &model.TLS{Subject: "CN=www.example.com", DNSNames: []string{"www.example.com"}},
	}}
	res.AXFR = []model.AXFR{{NS: "ns1.example.com", OK: true, Records: []string{"a", "b"}}}
	res.Wildcard = model.Wildcard{Enabled: true, IPs: []string{"192.0.2.99"}, Filtered: 3}

	data := buildGraph(res)
	if len(data.nodes) < 10 {
		t.Fatalf("nodes = %d, want a connected graph", len(data.nodes))
	}
	if len(data.links) < 10 {
		t.Fatalf("links = %d, want relationships", len(data.links))
	}

	labels := make(map[string]bool, len(data.nodes))
	for _, n := range data.nodes {
		if labels[n.Name] {
			t.Fatalf("duplicate node label %q", n.Name)
		}
		labels[n.Name] = true
	}
	for _, want := range []string{
		"example.com",
		"A · example.com",
		"ip · 192.0.2.1",
		"host · www.example.com",
		"NS · ns1.example.com",
		"MX · mail.example.com",
		"source · crt.sh",
		"SRV · _sip._tcp.example.com:5060",
		"HTTPS · www.example.com [200]",
		"TLS · CN=www.example.com",
		"AXFR · ns1.example.com (2 records)",
	} {
		if !labels[want] {
			t.Errorf("missing graph node %q", want)
		}
	}
	for _, l := range data.links {
		src, _ := l.Source.(string)
		dst, _ := l.Target.(string)
		if !labels[src] || !labels[dst] {
			t.Errorf("link references missing node: %v -> %v", l.Source, l.Target)
		}
	}
}

func TestRenderGraph(t *testing.T) {
	res, _ := fixture(t)
	var buf bytes.Buffer
	if err := renderGraph(&buf, res); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"Subsoil findings", "force", "echarts", "ip · 192.0.2.1"} {
		if !strings.Contains(out, want) {
			t.Errorf("graph HTML missing %q", want)
		}
	}
}
