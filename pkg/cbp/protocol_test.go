package cbp

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSessionReadyDataStreamsCapability(t *testing.T) {
	var ready SessionReady
	if err := json.Unmarshal([]byte(`{"session_id":1,"data_streams":true,"expires_at":"2026-11-24T00:00:00Z"}`), &ready); err != nil {
		t.Fatal(err)
	}
	if !ready.DataStreams {
		t.Fatal("data_streams capability was not decoded")
	}
}

func TestDataStreamOpenAckFrames(t *testing.T) {
	openPayload, err := MarshalPayload(DataStreamOpen{Network: "tcp", Address: "example.com:443"})
	if err != nil {
		t.Fatal(err)
	}
	var gotOpen DataStreamOpen
	if err := UnmarshalPayload(openPayload, &gotOpen); err != nil {
		t.Fatal(err)
	}
	if gotOpen.Network != "tcp" || gotOpen.Address != "example.com:443" {
		t.Fatalf("open = %#v", gotOpen)
	}

	ackPayload, err := MarshalPayload(DataStreamAck{OK: true})
	if err != nil {
		t.Fatal(err)
	}
	var gotAck DataStreamAck
	if err := UnmarshalPayload(ackPayload, &gotAck); err != nil {
		t.Fatal(err)
	}
	if !gotAck.OK {
		t.Fatalf("ack = %#v", gotAck)
	}

	var buf bytes.Buffer
	if err := WriteControlFrame(&buf, Envelope{Type: DataStreamOpenType, Payload: openPayload}); err != nil {
		t.Fatal(err)
	}
	env, err := ReadControlFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if env.Type != DataStreamOpenType {
		t.Fatalf("frame type = %q", env.Type)
	}
}
