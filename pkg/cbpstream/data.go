package cbpstream

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ersonw/mosdns-v4/pkg/cbp"
	"github.com/quic-go/quic-go"
)

const (
	defaultDataDialTimeout = 5 * time.Second
	dataStreamOpenTimeout  = 10 * time.Second
)

// dataPlane is the authenticated QUIC connection that carries logical data
// streams. It is separate from the control/TLS connection so a large TCP
// transfer cannot occupy the control writer and delay AUTH/RESOLVE/ACK frames.
type dataPlane struct {
	qconn quic.Connection
}

type dataStreamTargetError struct {
	address string
	reason  string
}

func (e *dataStreamTargetError) Error() string {
	return fmt.Sprintf("cbpstream: data stream %s: %s", e.address, e.reason)
}

// dataStreamConn exposes one QUIC stream as a net.Conn. Closing it must cancel
// the read side too; quic.Stream.Close only closes the write direction.
type dataStreamConn struct {
	stream quic.Stream
	local  net.Addr
	remote net.Addr
}

func (c *dataStreamConn) Read(p []byte) (int, error)  { return c.stream.Read(p) }
func (c *dataStreamConn) Write(p []byte) (int, error) { return c.stream.Write(p) }

func (c *dataStreamConn) Close() error {
	c.stream.CancelRead(0)
	return c.stream.Close()
}

func (c *dataStreamConn) LocalAddr() net.Addr                { return c.local }
func (c *dataStreamConn) RemoteAddr() net.Addr               { return c.remote }
func (c *dataStreamConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *dataStreamConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *dataStreamConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

func (c *Client) attachData(ctx context.Context) error {
	addresses := c.dataAddresses()
	if len(addresses) == 0 {
		return errors.New("cbpstream: node advertised data streams but no data address")
	}
	plane, err := dialDataPlane(ctx, c.cfg, c.ready, addresses)
	if err != nil {
		return err
	}
	c.dataMu.Lock()
	if c.isClosedLocked() {
		c.dataMu.Unlock()
		_ = plane.qconn.CloseWithError(0, "client closed")
		return errors.New("cbpstream: client closed")
	}
	c.data = plane
	c.dataErr = nil
	c.dataMu.Unlock()
	return nil
}

func (c *Client) isClosedLocked() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func (c *Client) dataAddresses() []string {
	seen := make(map[string]struct{}, len(c.ready.DataAddresses)+len(c.cfg.DataAddrs)+3)
	out := make([]string, 0, len(c.ready.DataAddresses)+len(c.cfg.DataAddrs)+3)
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		host, port, err := net.SplitHostPort(value)
		if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
			return
		}
		host = strings.Trim(host, "[]")
		if host == "0.0.0.0" || host == "::" {
			return
		}
		normalized := net.JoinHostPort(host, port)
		if _, ok := seen[normalized]; ok {
			return
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	for _, address := range c.ready.DataAddresses {
		add(address)
	}
	for _, address := range c.cfg.DataAddrs {
		add(address)
	}
	add(c.ready.DataAddr)
	// LAN is last: it is useful on the same private network, but a relayed or
	// remote mosdns must not spend its first handshake window on it.
	add(c.ready.LANDataAddr)
	return out
}

func dialDataPlane(ctx context.Context, cfg Config, ready cbp.SessionReady, addresses []string) (*dataPlane, error) {
	token, err := base64.RawURLEncoding.DecodeString(ready.DataToken)
	if err != nil || len(token) == 0 {
		return nil, errors.New("cbp: bad data token")
	}
	if cfg.TLSConfig == nil {
		cfg.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	timeout := cfg.DataDialTimeout
	if timeout <= 0 {
		timeout = defaultDataDialTimeout
	}
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}
	if timeout <= 0 {
		return nil, context.DeadlineExceeded
	}

	var lastErr error
	for _, address := range addresses {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		tlsCfg := cfg.TLSConfig.Clone()
		tlsCfg.NextProtos = []string{cbp.ALPNData}
		// A relayed control session authenticated the coordinator's name, not
		// the node's data certificate. Use the data endpoint host there; a
		// direct session can keep the node name already validated on control.
		if tlsCfg.ServerName == "" || cfg.RelayAddr != "" {
			host, _, splitErr := net.SplitHostPort(address)
			if splitErr == nil {
				tlsCfg.ServerName = strings.Trim(host, "[]")
			}
		}
		// A handshake covers UDP reachability and certificate validation;
		// an address that answers ICMP but filters the QUIC port is skipped.
		qctx, cancel := context.WithTimeout(ctx, timeout)
		qconn, err := quic.DialAddr(qctx, address, tlsCfg, &quic.Config{
			EnableDatagrams:       true,
			MaxIdleTimeout:        60 * time.Second,
			KeepAlivePeriod:       20 * time.Second,
			MaxIncomingStreams:    -1,
			MaxIncomingUniStreams: -1,
		})
		cancel()
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", address, err)
			continue
		}
		bind := cbp.DataPacket{
			Type:      cbp.DataTypeBind,
			SessionID: ready.SessionID,
			FragCount: 1,
			Payload:   token,
		}
		buf, err := bind.Encode()
		if err != nil {
			_ = qconn.CloseWithError(1, "bad bind")
			lastErr = err
			continue
		}
		if err := qconn.SendMessage(buf); err != nil {
			_ = qconn.CloseWithError(1, "bind send failed")
			lastErr = fmt.Errorf("%s: send bind: %w", address, err)
			continue
		}
		return &dataPlane{qconn: qconn}, nil
	}
	if lastErr == nil {
		lastErr = errors.New("cbp: no data address available")
	}
	return nil, lastErr
}

func (p *dataPlane) usable() bool {
	return p != nil && p.qconn != nil && p.qconn.Context().Err() == nil
}

func (c *Client) OpenDataStream(ctx context.Context, network, address string) (net.Conn, error) {
	if network == "" {
		network = "tcp"
	}
	if network != "tcp" {
		return nil, fmt.Errorf("cbpstream: unsupported data-stream network %q", network)
	}
	c.dataMu.RLock()
	plane := c.data
	ready := c.ready
	c.dataMu.RUnlock()
	if !ready.DataStreams {
		return nil, cbp.ErrDataStreamsUnsupported
	}
	if !plane.usable() {
		return nil, errors.New("cbpstream: QUIC data connection is not attached")
	}
	stream, err := plane.qconn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("cbpstream: open QUIC stream: %w", err)
	}
	deadline := time.Now().Add(dataStreamOpenTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = stream.SetDeadline(deadline)
	raw, err := cbp.MarshalPayload(cbp.DataStreamOpen{Network: network, Address: address})
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	if err := cbp.WriteControlFrame(stream, cbp.Envelope{Type: cbp.DataStreamOpenType, Payload: raw}); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("cbpstream: write data-stream open: %w", err)
	}
	env, err := cbp.ReadControlFrame(stream)
	if err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("cbpstream: read data-stream ack: %w", err)
	}
	if env.Type != cbp.DataStreamAckType {
		_ = stream.Close()
		return nil, fmt.Errorf("cbpstream: unexpected data-stream reply %q", env.Type)
	}
	var ack cbp.DataStreamAck
	if err := cbp.UnmarshalPayload(env.Payload, &ack); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("cbpstream: decode data-stream ack: %w", err)
	}
	if !ack.OK {
		_ = stream.Close()
		if ack.Error == "" {
			ack.Error = "node rejected stream"
		}
		return nil, &dataStreamTargetError{address: address, reason: ack.Error}
	}
	_ = stream.SetDeadline(time.Time{})
	return &dataStreamConn{stream: stream, local: plane.qconn.LocalAddr(), remote: plane.qconn.RemoteAddr()}, nil
}

// OpenStreamAuto preserves the control stream as the stable default. It tries
// the opt-in QUIC data stream only when the configuration enables it and the
// node advertised the capability; a transport-level failure falls back for the
// rest of this session, while a target rejection does not disable the path.
func (c *Client) OpenStreamAuto(ctx context.Context, network, address string) (net.Conn, error) {
	c.dataMu.RLock()
	enabled := c.cfg.UseDataStreams
	broken := c.dataStreamsBroken
	plane := c.data
	ready := c.ready.DataStreams
	c.dataMu.RUnlock()
	if !enabled || broken || !ready || !plane.usable() {
		return c.OpenStream(ctx, network, address)
	}
	dataCtx, cancel := context.WithTimeout(ctx, dataStreamOpenTimeout)
	conn, err := c.OpenDataStream(dataCtx, network, address)
	cancel()
	if err == nil {
		return conn, nil
	}
	var target *dataStreamTargetError
	if !errors.As(err, &target) {
		c.dataMu.Lock()
		c.dataStreamsBroken = true
		c.dataMu.Unlock()
	}
	return c.OpenStream(ctx, network, address)
}

func (c *Client) DataStreamsAvailable() bool {
	c.dataMu.RLock()
	defer c.dataMu.RUnlock()
	return c.cfg.UseDataStreams && !c.dataStreamsBroken && c.ready.DataStreams && c.data.usable()
}

func (c *Client) DataStreamError() error {
	c.dataMu.RLock()
	defer c.dataMu.RUnlock()
	return c.dataErr
}

func (c *Client) closeData() {
	c.dataMu.Lock()
	plane := c.data
	c.data = nil
	c.dataMu.Unlock()
	if plane != nil {
		_ = plane.qconn.CloseWithError(0, "client closed")
	}
}
