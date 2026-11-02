package report

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/opts"

	"subsoil/internal/model"
)

const (
	maxGraphNodes = 2500
	maxGraphLinks = 5000
)

const (
	graphTarget = iota
	graphRecord
	graphHost
	graphIP
	graphNS
	graphMail
	graphService
	graphHTTP
	graphTLS
	graphSource
	graphAXFR
	graphWildcard
)

type graphCategoryDef struct {
	name   string
	color  string
	symbol string
	size   float32
}

var graphCategoryDefs = []graphCategoryDef{
	{"target", "#d1495b", "roundRect", 72},
	{"DNS record", "#3d5a80", "rect", 30},
	{"subdomain", "#2a9d8f", "circle", 38},
	{"IP address", "#e9c46a", "diamond", 28},
	{"nameserver", "#8e7dbe", "triangle", 28},
	{"mail", "#f4a261", "pin", 28},
	{"service", "#6a994e", "roundRect", 30},
	{"HTTP", "#1d3557", "circle", 30},
	{"TLS", "#bc4749", "rect", 26},
	{"source", "#8d99ae", "circle", 20},
	{"zone transfer", "#7f5539", "diamond", 28},
	{"wildcard", "#d4a373", "triangle", 34},
}

type graphData struct {
	nodes      []opts.GraphNode
	links      []opts.GraphLink
	categories []*opts.GraphCategory
	truncated  bool
}

type graphBuilder struct {
	nodes      map[string]*opts.GraphNode
	nodeOrder  []string
	labels     map[string]string
	links      []opts.GraphLink
	linkSeen   map[string]struct{}
	categories []*opts.GraphCategory
	truncated  bool
}

func newGraphBuilder() *graphBuilder {
	b := &graphBuilder{
		nodes:    make(map[string]*opts.GraphNode),
		labels:   make(map[string]string),
		linkSeen: make(map[string]struct{}),
	}
	for _, def := range graphCategoryDefs {
		b.categories = append(b.categories, &opts.GraphCategory{
			Name:      def.name,
			ItemStyle: &opts.ItemStyle{Color: def.color},
		})
	}
	return b
}

func (b *graphBuilder) addNode(id, label string, category int, size float32) string {
	if n, ok := b.nodes[id]; ok {
		return n.Name
	}
	if len(b.nodes) >= maxGraphNodes {
		b.truncated = true
		return ""
	}
	label = cleanText(strings.TrimSpace(label))
	if label == "" {
		label = "(unnamed)"
	}
	unique := label
	for n := 2; ; n++ {
		if _, exists := b.labels[unique]; !exists {
			break
		}
		unique = fmt.Sprintf("%s #%d", label, n)
	}
	if category < 0 || category >= len(graphCategoryDefs) {
		category = graphRecord
	}
	nodeSize := size
	if nodeSize <= 0 {
		nodeSize = graphCategoryDefs[category].size
	}
	node := opts.GraphNode{
		Name:       unique,
		Value:      1,
		Category:   category,
		Symbol:     graphCategoryDefs[category].symbol,
		SymbolSize: nodeSize,
	}
	b.nodes[id] = &node
	b.nodeOrder = append(b.nodeOrder, id)
	b.labels[unique] = id
	return unique
}

func (b *graphBuilder) addLink(source, target, relation string) {
	if source == "" || target == "" || source == target {
		return
	}
	key := source + "\x00" + target + "\x00" + relation
	if _, ok := b.linkSeen[key]; ok {
		return
	}
	if len(b.links) >= maxGraphLinks {
		b.truncated = true
		return
	}
	b.linkSeen[key] = struct{}{}
	b.links = append(b.links, opts.GraphLink{
		Source: source,
		Target: target,
		Value:  1,
		Label: &opts.EdgeLabel{
			Show:      opts.Bool(false),
			Formatter: relation,
			FontSize:  9,
			Color:     "#8a8a8a",
		},
		LineStyle: &opts.LineStyle{
			Color:     "source",
			Width:     1,
			Opacity:   opts.Float(0.5),
			Curveness: 0.08,
		},
	})
}

func (b *graphBuilder) addIP(ip string) string {
	ip = graphName(ip)
	if ip == "" {
		return ""
	}
	return b.addNode("ip:"+strings.ToLower(ip), "ip · "+ip, graphIP, 0)
}

func (b *graphBuilder) addHost(name string) string {
	name = graphName(name)
	if name == "" {
		return ""
	}
	return b.addNode("host:"+strings.ToLower(name), "host · "+name, graphHost, 0)
}

func (b *graphBuilder) addNS(name string) string {
	name = graphName(name)
	if name == "" {
		return ""
	}
	return b.addNode("ns:"+strings.ToLower(name), "NS · "+name, graphNS, 0)
}

func (b *graphBuilder) addMail(name string) string {
	name = graphName(name)
	if name == "" {
		return ""
	}
	return b.addNode("mx:"+strings.ToLower(name), "MX · "+name, graphMail, 0)
}

func (b *graphBuilder) addSource(name string) string {
	name = graphName(name)
	if name == "" {
		return ""
	}
	return b.addNode("source:"+strings.ToLower(name), "source · "+name, graphSource, 0)
}

func buildGraph(res *model.Result) *graphData {
	b := newGraphBuilder()
	domain := graphName(res.Domain)
	if domain == "" {
		domain = "target"
	}
	root := b.addNode("domain:"+strings.ToLower(domain), domain, graphTarget, 0)

	for _, rs := range res.Records {
		typ := strings.ToUpper(strings.TrimSpace(rs.Type))
		name := graphName(rs.Name)
		if typ == "" || name == "" {
			continue
		}
		record := b.addNode("record:"+strings.ToLower(typ)+":"+strings.ToLower(name),
			recordLabel(rs)+" · "+name, graphRecord, 0)
		if record == "" {
			continue
		}
		b.addLink(root, record, typ)
		for _, rr := range rs.RRs {
			value := strings.TrimSpace(rrValue(typ, rr))
			switch typ {
			case "A", "AAAA":
				b.addLink(record, b.addIP(value), typ)
			case "NS":
				b.addLink(record, b.addNS(value), typ)
			case "MX":
				pref, target := graphMX(value)
				rel := "MX"
				if pref != "" {
					rel += " " + pref
				}
				b.addLink(record, b.addMail(target), rel)
			case "CNAME":
				b.addLink(record, b.addHost(value), typ)
			case "SRV":
				port, target := graphSRV(value)
				rel := "SRV"
				if port != "" {
					rel += " " + port
				}
				b.addLink(record, b.addHost(target), rel)
			case "PTR":
				b.addLink(record, b.addHost(value), typ)
			}
		}
	}

	for _, h := range res.Hosts {
		name := graphName(h.Name)
		if name == "" {
			continue
		}
		host := b.addNode("host:"+strings.ToLower(name), "host · "+name, graphHost, 0)
		if host == "" {
			continue
		}
		b.addLink(root, host, "discovered")
		for _, ip := range h.IPs {
			b.addLink(host, b.addIP(ip), "A")
		}
		for _, ip := range h.AAAA {
			b.addLink(host, b.addIP(ip), "AAAA")
		}
		if h.CNAME != "" {
			b.addLink(host, b.addHost(h.CNAME), "CNAME")
		}
		for _, src := range h.Sources {
			b.addLink(host, b.addSource(src), "seen via")
		}
	}

	for _, s := range res.SRV {
		name := graphName(s.Name)
		target := graphName(s.Target)
		if name == "" || target == "" {
			continue
		}
		port := strconv.Itoa(int(s.Port))
		label := "SRV · " + name
		if s.Port != 0 {
			label += ":" + port
		}
		node := b.addNode("srv:"+strings.ToLower(name)+":"+strings.ToLower(target)+":"+port,
			label, graphService, 0)
		b.addLink(root, node, "SRV")
		b.addLink(node, b.addHost(target), "target")
	}

	for _, p := range res.PTR {
		ip := b.addIP(p.IP)
		if ip == "" {
			continue
		}
		for _, name := range p.Names {
			b.addLink(ip, b.addHost(name), "PTR")
		}
	}

	for _, h := range res.HTTP {
		host := graphName(h.Host)
		if host == "" {
			continue
		}
		scheme := strings.ToUpper(graphName(h.Scheme))
		if scheme == "" {
			scheme = "HTTP"
		}
		label := scheme + " · " + host
		if h.Status != 0 {
			label += fmt.Sprintf(" [%d]", h.Status)
		}
		node := b.addNode("http:"+strings.ToLower(scheme)+":"+strings.ToLower(host),
			label, graphHTTP, 0)
		b.addLink(b.addHost(host), node, "HTTP")
		if h.TLS != nil {
			subject := graphName(h.TLS.Subject)
			if subject == "" && len(h.TLS.DNSNames) > 0 {
				subject = graphName(h.TLS.DNSNames[0])
			}
			if subject != "" {
				cert := b.addNode("cert:"+strings.ToLower(subject), "TLS · "+subject, graphTLS, 0)
				b.addLink(node, cert, "TLS")
				for _, dn := range h.TLS.DNSNames {
					b.addLink(cert, b.addHost(dn), "SAN")
				}
			}
		}
	}

	for _, z := range res.AXFR {
		ns := graphName(z.NS)
		if ns == "" {
			continue
		}
		label := "AXFR · " + ns
		if z.OK {
			label += fmt.Sprintf(" (%d records)", len(z.Records))
		} else {
			label += " (failed)"
		}
		node := b.addNode("axfr:"+strings.ToLower(ns), label, graphAXFR, 0)
		b.addLink(root, node, "AXFR")
		b.addLink(b.addNS(ns), node, "zone transfer")
	}

	if res.Wildcard.Enabled {
		label := "wildcard DNS"
		if res.Wildcard.Filtered > 0 {
			label += fmt.Sprintf(" · %d filtered", res.Wildcard.Filtered)
		}
		node := b.addNode("wildcard:"+strings.ToLower(domain), label, graphWildcard, 0)
		b.addLink(root, node, "wildcard")
		for _, ip := range res.Wildcard.IPs {
			b.addLink(node, b.addIP(ip), "wildcard A")
		}
		for _, cname := range res.Wildcard.CNAMEs {
			b.addLink(node, b.addHost(cname), "wildcard CNAME")
		}
	}

	if len(b.links) > 0 && len(b.nodes) <= 80 {
		for i := range b.links {
			b.links[i].Label.Show = opts.Bool(true)
		}
	}

	data := &graphData{categories: b.categories, truncated: b.truncated}
	for _, id := range b.nodeOrder {
		data.nodes = append(data.nodes, *b.nodes[id])
	}
	data.links = b.links
	return data
}

func graphName(s string) string {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "."))
	return cleanText(strings.NewReplacer("<", "‹", ">", "›").Replace(s))
}

func graphMX(value string) (preference, target string) {
	fields := strings.Fields(value)
	if len(fields) >= 2 {
		return fields[0], fields[len(fields)-1]
	}
	return "", value
}

func graphSRV(value string) (port, target string) {
	fields := strings.Fields(value)
	if len(fields) >= 2 {
		if len(fields) >= 4 {
			return fields[2], fields[len(fields)-1]
		}
		return "", fields[len(fields)-1]
	}
	return "", value
}

func writeGraph(path string, res *model.Result) error {
	var buf bytes.Buffer
	if err := renderGraph(&buf, res); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func renderGraph(w io.Writer, res *model.Result) error {
	data := buildGraph(res)
	showLabels := len(data.nodes) <= 180

	title := "Subsoil findings"
	subtitle := fmt.Sprintf("%s · v%s · %d entities · %d links · drag/scroll to explore",
		graphName(res.Domain), res.Version, len(data.nodes), len(data.links))
	if data.truncated {
		subtitle += " · graph truncated"
	}

	names := make([]string, 0, len(graphCategoryDefs))
	colors := make(opts.Colors, 0, len(graphCategoryDefs))
	for _, def := range graphCategoryDefs {
		names = append(names, def.name)
		colors = append(colors, def.color)
	}

	graph := charts.NewGraph()
	graph.SetGlobalOptions(
		charts.WithInitializationOpts(opts.Initialization{
			PageTitle: "Subsoil findings · " + graphName(res.Domain),
			Width:     "100%",
			Height:    "900px",
		}),
		charts.WithTitleOpts(opts.Title{Title: title, Subtitle: subtitle}),
		charts.WithTooltipOpts(opts.Tooltip{
			Trigger: "item",
			Formatter: opts.FuncOpts(`function (p) {
  if (p.dataType === 'edge') {
    return p.data && p.data.label && p.data.label.formatter ? p.data.label.formatter : '';
  }
  return p.data && p.data.name ? p.data.name : (p.name || '');
}`),
		}),
		charts.WithLegendOpts(opts.Legend{
			Show:   opts.Bool(true),
			Type:   "scroll",
			Bottom: "0",
			Data:   names,
		}),
		charts.WithColorsOpts(opts.Colors(colors)),
	)
	graph.AddSeries("findings", data.nodes, data.links,
		charts.WithGraphChartOpts(opts.GraphChart{
			Layout:             "force",
			Force:              &opts.GraphForce{Repulsion: 180, Gravity: 0.08, EdgeLength: 80},
			Roam:               opts.Bool(true),
			Draggable:          opts.Bool(true),
			FocusNodeAdjacency: opts.Bool(true),
			Categories:         data.categories,
			LineStyle: &opts.LineStyle{
				Color:     "source",
				Width:     1,
				Opacity:   opts.Float(0.5),
				Curveness: 0.08,
			},
		}),
		charts.WithLabelOpts(opts.Label{
			Show:     opts.Bool(showLabels),
			Position: "right",
			FontSize: 10,
			Color:    "#333",
		}),
	)
	return graph.Render(w)
}
