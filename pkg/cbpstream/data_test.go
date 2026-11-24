package cbpstream

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ersonw/mosdns-v4/pkg/cbp"
	"github.com/quic-go/quic-go"
)

func TestDataStreamCarriesTCPOverQUIC(t *testing.T) {
	cert := streamTestCertificate(t)
	controlLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer controlLn.Close()
	controlTLS := tls.NewListener(controlLn, &tls.Config{Certificates: []tls.Certificate{cert}})

	dataLn, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{cbp.ALPNData},
	}, &quic.Config{
		EnableDatagrams:       true,
		MaxIncomingStreams:    16,
		MaxIncomingUniStreams: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dataLn.Close()

	dataAddr := dataLn.Addr().String()
	dataToken := base64.RawURLEncoding.EncodeToString([]byte("data-token"))
	serverErr := make(chan error, 2)

	go func() {
		conn, err := controlTLS.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		if err := cbp.WriteControlFrame(conn, cbp.Envelope{
			Type: "HELLO_ACK",
			Payload: mustStreamPayload(t, map[string]any{
				"nonce":         base64.RawURLEncoding.EncodeToString([]byte("data-stream-test")),
				"version":       1,
				"auth_required": true,
			}),
		}); err != nil {
			serverErr <- err
			return
		}
		env, err := cbp.ReadControlFrame(conn)
		if err != nil || env.Type != "AUTH" {
			serverErr <- err
			return
		}
		if err := cbp.WriteControlFrame(conn, cbp.Envelope{
			Type: "SESSION_READY",
			Payload: mustStreamPayload(t, map[string]any{
				"session_id":   99,
				"data_addr":    dataAddr,
				"data_token":   dataToken,
				"data_streams": true,
				"expires_at":   time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			}),
		}); err != nil {
			serverErr <- err
		}
		// Keep the control session alive until the test closes the client.
		<-time.After(2 * time.Second)
	}()

	go func() {
		conn, err := dataLn.Accept(context.Background())
		if err != nil {
			serverErr <- err
			return
		}
		msg, err := conn.ReceiveMessage()
		if err != nil {
			serverErr <- err
			return
		}
		pkt, err := cbp.DecodeDataPacket(msg)
		if err != nil || pkt.Type != cbp.DataTypeBind || pkt.SessionID != 99 {
			serverErr <- err
			return
		}
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			serverErr <- err
			return
		}
		defer stream.Close()
		env, err := cbp.ReadControlFrame(stream)
		if err != nil || env.Type != cbp.DataStreamOpenType {
			serverErr <- err
			return
		}
		var open cbp.DataStreamOpen
		if err := cbp.UnmarshalPayload(env.Payload, &open); err != nil {
			serverErr <- err
			return
		}
		ackPayload, err := cbp.MarshalPayload(cbp.DataStreamAck{OK: true})
		if err != nil {
			serverErr <- err
			return
		}
		if err := cbp.WriteControlFrame(stream, cbp.Envelope{
			Type:    cbp.DataStreamAckType,
			Payload: ackPayload,
		}); err != nil {
			serverErr <- err
			return
		}
		buf := make([]byte, 64)
		n, err := stream.Read(buf)
		if err != nil {
			serverErr <- err
			return
		}
		if _, err := stream.Write(append([]byte("reply:"), buf[:n]...)); err != nil {
			serverErr <- err
		}
	}()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := Dial(ctx, Config{
		ControlAddr: controlLn.Addr().String(),
		TLSConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
		},
		Token:           "test-token",
		DeviceID:        "test-device",
		PrivateKey:      privateKey,
		DialTimeout:     5 * time.Second,
		UseDataStreams:  true,
		DataDialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if !client.DataStreamsAvailable() {
		t.Fatalf("data streams unavailable: %v", client.DataStreamError())
	}
	conn, err := client.OpenStreamAuto(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := io.ReadAtLeast(conn, buf, len("reply:hello"))
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "reply:hello" {
		t.Fatalf("response = %q", buf[:n])
	}
}

func TestDataStreamTargetErrorClassification(t *testing.T) {
	var target *dataStreamTargetError
	err := error(&dataStreamTargetError{address: "blocked:443", reason: "dial failed"})
	if !errors.As(err, &target) {
		t.Fatal("target error was not recognized")
	}
	transport := io.ErrUnexpectedEOF
	if errors.As(transport, &target) {
		t.Fatal("transport error was misclassified as target error")
	}
}
