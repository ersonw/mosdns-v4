package exec_script

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/executable_seq"
	"github.com/ersonw/mosdns-v4/pkg/query_context"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const PluginType = "exec_script"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

type Args struct {
	ScriptPath string `yaml:"script_path"`
	DedupTTL   int    `yaml:"dedup_ttl"`
	Async      *bool  `yaml:"async"`
}

type ExecScript struct {
	*coremain.BP
	args *Args

	dedupTTL time.Duration
	async    bool
	ipCache  map[string]time.Time
	mu       sync.Mutex
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return newExecScript(bp, args.(*Args))
}

func newExecScript(bp *coremain.BP, args *Args) (*ExecScript, error) {
	if args.ScriptPath == "" {
		return nil, fmt.Errorf("script_path is required")
	}

	dedupTTL := 300 * time.Second
	if args.DedupTTL > 0 {
		dedupTTL = time.Duration(args.DedupTTL) * time.Second
	}

	async := true
	if args.Async != nil {
		async = *args.Async
	}

	return &ExecScript{
		BP:       bp,
		args:     args,
		dedupTTL: dedupTTL,
		async:    async,
		ipCache:  make(map[string]time.Time),
	}, nil
}

func (p *ExecScript) isDuplicated(ip string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	if last, ok := p.ipCache[ip]; ok && now.Sub(last) < p.dedupTTL {
		return true
	}
	p.ipCache[ip] = now

	for k, v := range p.ipCache {
		if now.Sub(v) > p.dedupTTL {
			delete(p.ipCache, k)
		}
	}
	return false
}

func (p *ExecScript) runScript(ip, domain string) {
	if p.isDuplicated(ip) {
		return
	}

	cmd := exec.Command(p.args.ScriptPath, ip, domain)
	if err := cmd.Run(); err != nil {
		p.L().Warn("failed to exec script", zap.String("script", p.args.ScriptPath), zap.String("ip", ip), zap.Error(err))
	}
}

func (p *ExecScript) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	if err := executable_seq.ExecChainNode(ctx, qCtx, next); err != nil {
		return err
	}

	r := qCtx.R()
	if r == nil || len(r.Answer) == 0 {
		return nil
	}

	qname := ""
	if q := qCtx.Q(); q != nil && len(q.Question) > 0 {
		qname = strings.TrimSuffix(q.Question[0].Name, ".")
	}

	for _, rr := range r.Answer {
		var ip string
		switch record := rr.(type) {
		case *dns.A:
			ip = record.A.String()
		case *dns.AAAA:
			ip = record.AAAA.String()
		default:
			continue
		}

		if p.async {
			go p.runScript(ip, qname)
		} else {
			p.runScript(ip, qname)
		}
	}

	return nil
}

func (p *ExecScript) Close() error {
	return nil
}
