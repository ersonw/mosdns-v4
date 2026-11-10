package fakeipnat

import (
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/executable_seq"
	"github.com/ersonw/mosdns-v4/pkg/query_context"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	_ "modernc.org/sqlite"
)

const PluginType = "fakeip_nat"

var validTableName = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

type Args struct {
	DBPath      string `yaml:"db_path"`      // SQLite 路径，默认: "/config/mosdns/fakeip.db"
	TablePrefix string `yaml:"table_prefix"` // 数据库表名前缀，默认: "default"
	IPv4Range   string `yaml:"ipv4_range"`   // 虚拟 IP 段，默认: "198.18.0.0/15"
	Script      string `yaml:"script"`       // 回调脚本路径，默认: "/config/mosdns/nat_map.sh"
	TTL         uint32 `yaml:"ttl"`          // 返回的 DNS TTL，默认: 60
	NextHop     string `yaml:"next_hop"`     // 可选：指定真实目标 IP 的默认路由下一跳网关（不填则使用系统默认路由）
	NextHopDev  string `yaml:"next_hop_dev"` // 可选：指定下一跳出站网卡名称（不填则不指定 dev 参数）
}

type FakeIPNatPlugin struct {
	*coremain.BP
	db          *sql.DB
	dbPath      string
	tablePrefix string
	mapTable    string
	ipTable     string
	cidr        string
	prefix      netip.Prefix
	script      string
	ttl         uint32
	nextHop     string
	nextHopDev  string
	mu          sync.Mutex
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	cfg := args.(*Args)

	if cfg.DBPath == "" {
		cfg.DBPath = "/config/mosdns/fakeip.db"
	}
	if cfg.TablePrefix == "" {
		cfg.TablePrefix = "default"
	}
	if cfg.IPv4Range == "" {
		cfg.IPv4Range = "198.18.0.0/15"
	}
	if cfg.Script == "" {
		cfg.Script = "/config/mosdns/nat_map.sh"
	}
	if cfg.TTL == 0 {
		cfg.TTL = 60
	}

	if !validTableName.MatchString(cfg.TablePrefix) {
		return nil, fmt.Errorf("invalid table_prefix %q: only alphanumeric and underscore allowed", cfg.TablePrefix)
	}

	prefix, err := netip.ParsePrefix(cfg.IPv4Range)
	if err != nil {
		return nil, fmt.Errorf("invalid ipv4_range: %w", err)
	}

	if cfg.NextHop != "" {
		if _, err := netip.ParseAddr(cfg.NextHop); err != nil {
			return nil, fmt.Errorf("invalid next_hop IP %q: %w", cfg.NextHop, err)
		}
	}

	db, err := sql.Open("sqlite", cfg.DBPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite failed: %w", err)
	}

	mapTable := cfg.TablePrefix + "_mapping"
	ipTable := cfg.TablePrefix + "_real_ips"
	idxName := "idx_" + cfg.TablePrefix + "_real_ips_domain"

	initSQL := fmt.Sprintf(`
	CREATE TABLE IF NOT EXISTS %s (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT UNIQUE NOT NULL,
		fake_ip TEXT UNIQUE NOT NULL,
		created_at INTEGER DEFAULT 0
	);
	CREATE TABLE IF NOT EXISTS %s (
		domain TEXT NOT NULL,
		real_ip TEXT NOT NULL,
		last_seen INTEGER DEFAULT 0,
		PRIMARY KEY (domain, real_ip)
	);
	CREATE INDEX IF NOT EXISTS %s ON %s(domain);`,
		mapTable, ipTable, idxName, ipTable,
	)

	if _, err := db.Exec(initSQL); err != nil {
		return nil, fmt.Errorf("init tables failed: %w", err)
	}

	return &FakeIPNatPlugin{
		BP:          bp,
		db:          db,
		dbPath:      cfg.DBPath,
		tablePrefix: cfg.TablePrefix,
		mapTable:    mapTable,
		ipTable:     ipTable,
		cidr:        cfg.IPv4Range,
		prefix:      prefix,
		script:      cfg.Script,
		ttl:         cfg.TTL,
		nextHop:     strings.TrimSpace(cfg.NextHop),
		nextHopDev:  strings.TrimSpace(cfg.NextHopDev),
	}, nil
}

func (p *FakeIPNatPlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()
	if len(q.Question) == 0 {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	question := q.Question[0]
	if question.Qtype == dns.TypeAAAA {
		emptyResp := new(dns.Msg)
		emptyResp.SetReply(q)
		emptyResp.RecursionAvailable = true
		qCtx.SetResponse(emptyResp)
		return nil
	}

	alreadyResolved := (qCtx.R() != nil)
	if !alreadyResolved {
		if err := executable_seq.ExecChainNode(ctx, qCtx, next); err != nil {
			return err
		}
	}

	resp := qCtx.R()
	if resp != nil && question.Qtype == dns.TypeA {
		var realIPs []string
		for _, ans := range resp.Answer {
			if aRecord, ok := ans.(*dns.A); ok {
				realIPs = append(realIPs, aRecord.A.String())
			}
		}

		if len(realIPs) > 0 {
			domain := strings.TrimSuffix(question.Name, ".")
			fakeIP, err := p.recordAndAllocate(domain, realIPs)
			if err != nil {
				p.L().Error("sqlite record fakeip failed", zap.String("domain", domain), zap.Error(err))
			} else {
				if p.script != "" {
					go p.runHookScript(fakeIP, domain, strings.Join(realIPs, ","))
				}

				newResp := new(dns.Msg)
				newResp.SetReply(q)
				newResp.RecursionAvailable = true
				newResp.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   question.Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    p.ttl,
						},
						A: net.ParseIP(fakeIP),
					},
				}
				qCtx.SetResponse(newResp)
			}
		}
	}

	if alreadyResolved {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}
	return nil
}

func (p *FakeIPNatPlugin) recordAndAllocate(domain string, realIPs []string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now().Unix()
	var fakeIP string
	querySQL := fmt.Sprintf("SELECT fake_ip FROM %s WHERE domain = ?", p.mapTable)
	err := p.db.QueryRow(querySQL, domain).Scan(&fakeIP)

	if err == sql.ErrNoRows {
		insertSQL := fmt.Sprintf("INSERT INTO %s (domain, fake_ip, created_at) VALUES (?, 'pending', ?)", p.mapTable)
		res, err := p.db.Exec(insertSQL, domain, now)
		if err != nil {
			return "", err
		}
		id, err := res.LastInsertId()
		if err != nil {
			return "", err
		}

		base := p.prefix.Addr().As4()
		baseUint := binary.BigEndian.Uint32(base[:])
		ones, bits := p.prefix.Bits(), p.prefix.Addr().BitLen()
		maxHosts := uint32(1<<(bits-ones)) - 2
		offset := uint32(id)%maxHosts + 1
		targetUint := baseUint + offset
		fakeIP = fmt.Sprintf("%d.%d.%d.%d", byte(targetUint>>24), byte(targetUint>>16), byte(targetUint>>8), byte(targetUint))

		updateSQL := fmt.Sprintf("UPDATE %s SET fake_ip = ? WHERE id = ?", p.mapTable)
		if _, err := p.db.Exec(updateSQL, fakeIP, id); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}

	upsertIPSQL := fmt.Sprintf(`
		INSERT INTO %s (domain, real_ip, last_seen)
		VALUES (?, ?, ?)
		ON CONFLICT(domain, real_ip) DO UPDATE SET last_seen = excluded.last_seen`,
		p.ipTable,
	)
	for _, ip := range realIPs {
		_, _ = p.db.Exec(upsertIPSQL, domain, ip, now)
	}

	return fakeIP, nil
}

func (p *FakeIPNatPlugin) runHookScript(fakeIP, domain, latestIPs string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// 传参顺序:
	// $1 = 虚拟IP
	// $2 = 域名
	// $3 = 数据库路径
	// $4 = 本次解析到的全部真实IP (逗号分隔)
	// $5 = 配置的网段 (如 198.18.0.0/16)
	// $6 = 表名前缀 (如 oversea)
	// $7 = 默认路由下一跳网关 (未配置为空字符串 "")
	// $8 = 下一跳出站网卡 (未配置为空字符串 "")
	cmd := exec.CommandContext(ctx, "/bin/sh", p.script, fakeIP, domain, p.dbPath, latestIPs, p.cidr, p.tablePrefix, p.nextHop, p.nextHopDev)
	if out, err := cmd.CombinedOutput(); err != nil {
		p.L().Error("hook script failed", zap.String("fake_ip", fakeIP), zap.String("domain", domain), zap.ByteString("output", out), zap.Error(err))
	}
}
