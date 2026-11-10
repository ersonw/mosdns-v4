package coremain

import (
	"errors"
	"fmt"
	"github.com/liang-hiwin/mosdns-v4/pkg/server"
	"github.com/liang-hiwin/mosdns-v4/pkg/server/dns_handler"
	"github.com/liang-hiwin/mosdns-v4/pkg/server/http_handler"
	"github.com/pires/go-proxyproto"
	"go.uber.org/zap"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const defaultQueryTimeout = time.Second * 5
const (
	defaultIdleTimeout = time.Second * 10
)

func (m *Mosdns) startServers(cfg *ServerConfig) error {
	if len(cfg.Listeners) == 0 {
		return errors.New("no server listener is configured")
	}
	if len(cfg.Exec) == 0 {
		return errors.New("empty entry")
	}

	entry := m.execs[cfg.Exec]
	if entry == nil {
		return fmt.Errorf("cannot find entry %s", cfg.Exec)
	}

	queryTimeout := defaultQueryTimeout
	if cfg.Timeout > 0 {
		queryTimeout = time.Duration(cfg.Timeout) * time.Second
	}

	dnsHandlerOpts := dns_handler.EntryHandlerOpts{
		Logger:             m.logger,
		Entry:              entry,
		QueryTimeout:       queryTimeout,
		RecursionAvailable: true,
	}
	dnsHandler, err := dns_handler.NewEntryHandler(dnsHandlerOpts)
	if err != nil {
		return fmt.Errorf("failed to init entry handler, %w", err)
	}

	for _, lc := range cfg.Listeners {
		if err := m.startServerListener(lc, dnsHandler, "/tmp/go-unix-socket"); err != nil {
			return err
		}
	}
	return nil
}

func (m *Mosdns) startServerListener(cfg *ServerListenerConfig, dnsHandler dns_handler.Handler, socketFile string) error {
	if len(cfg.Addr) == 0 {
		return errors.New("no address to bind")
	}

	m.logger.Info("starting server", zap.String("proto", cfg.Protocol), zap.String("addr", cfg.Addr))

	idleTimeout := defaultIdleTimeout
	if cfg.IdleTimeout > 0 {
		idleTimeout = time.Duration(cfg.IdleTimeout) * time.Second
	}

	httpOpts := http_handler.HandlerOpts{
		DNSHandler:   dnsHandler,
		Path:         cfg.URLPath,
		SrcIPHeader:  cfg.GetUserIPFromHeader,
		Logger:       m.logger,
	}

	httpHandler, err := http_handler.NewHandler(httpOpts)
	if err != nil {
		return fmt.Errorf("failed to init http handler, %w", err)
	}

	opts := server.ServerOpts{
		DNSHandler:  dnsHandler,
		HttpHandler: httpHandler,
		Cert:        cfg.Cert,
		Key:         cfg.Key,
		IdleTimeout: idleTimeout,
		Logger:      m.logger,
	}
	s := server.NewServer(opts)

	// helper func for proxy protocol listener
	requirePP := func(_ net.Addr) (proxyproto.Policy, error) {
		return proxyproto.REQUIRE, nil
	}

	var run func() error
	switch cfg.Protocol {
	case "", "udp":
		conn, err := net.ListenPacket("udp", cfg.Addr)
		if err != nil {
			return err
		}
		run = func() error { return s.ServeUDP(conn) }
	case "tcp":
		var l net.Listener
		var err error
		if cfg.Unix {
			l, err = createUnixListener("unix", socketFile)
		} else {
			l, err = net.Listen("tcp", cfg.Addr)
		}
		if err != nil {
			return err
		}
		if cfg.ProxyProtocol {
			l = &proxyproto.Listener{Listener: l, Policy: requirePP}
		}
		run = func() error { return s.ServeTCP(l) }
	case "tls", "dot":
		l, err := net.Listen("tcp", cfg.Addr)
		if err != nil {
			return err
		}
		if cfg.ProxyProtocol {
			l = &proxyproto.Listener{Listener: l, Policy: requirePP}
		}
		run = func() error { return s.ServeTLS(l) }
		// UNIX domain socket
	case "http":
		l, err := createUnixListener("unix", socketFile)
		if err != nil {
			return err
		}
		if cfg.ProxyProtocol {
			l = &proxyproto.Listener{Listener: l, Policy: requirePP}
		}
		run = func() error { return s.ServeHTTP(l) }

	////////
	case "https", "doh":
		l, err := net.Listen("tcp", cfg.Addr)
		if err != nil {
			return err
		}
		if cfg.ProxyProtocol {
			l = &proxyproto.Listener{Listener: l, Policy: requirePP}
		}
		run = func() error { return s.ServeHTTPS(l) }

	default:
		return fmt.Errorf("unknown protocol: [%s]", cfg.Protocol)
	}

	m.sc.Attach(func(done func(), closeSignal <-chan struct{}) {
		defer done()
		errChan := make(chan error, 1)
		go func() {
			errChan <- run()
		}()
		select {
		case err := <-errChan:
			m.sc.SendCloseSignal(fmt.Errorf("server exited, %w", err))
		case <-closeSignal:
		}
	})

	return nil
}

func createUnixListener(network, address string) (net.Listener, error) {
	if err := os.Remove(address); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}

	if err := os.Chmod(address, 0777); err != nil {
		l.Close()
		return nil, err
	}

	// Set up a signal handler to remove the socket file when the program is terminated
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		os.Remove(address)
		os.Exit(0)
	}()

	return l, nil
}
