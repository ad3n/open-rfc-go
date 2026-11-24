// SPDX-License-Identifier: Apache-2.0
// Fixtures ported from open-rfc test/message-server.test.ts at 847036d, Copyright 2026 Marian Zeis.

package msgserver

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

const (
	fixtureGroup     = "RFC_GROUP"
	loginrequestHex  = "2a2a4d4553534147452a2a0004002d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002082d2020202020202020202020202020202020202020202020202020202020202020202020202020200000"
	loginresponseHex = "2a2a4d4553534147452a2a0004002d20202020202020202020202020202020202020202020202020202020202020202020202020202000000001000000000000000002084d53475f5345525645522020202020202020202020202020202020202020202020202020202020200000"
	logoutrequestHex = "2a2a4d4553534147452a2a0004002d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000042d2020202020202020202020202020202020202020202020202020202020202020202020202020200000"
	grouprequestHex  = "2a2a4d4553534147452a2a0004004d53475f53455256455200000000000000000000000000000000000000000000000000000000000000000000000000000000000002012d20202020202020202020202020202020202020202020202020202020202020202020202020202000002c000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d5246435f47524f5550000000000000000000000000000000000000000000000000000000000000000100000000340000"
	groupresponseHex = "2a2a4d4553534147452a2a0004002d20202020202020202020202020202020202020202020202020202020202020202020202020202000000000000000000000000003014d53475f53455256455200000000000000000000000000000000000000000000000000000000000000002c000103000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d5246435f47524f555000000000000000000000000000000000000000000000000000000000000000010000000c8000106170702e6578616d706c652e7465737420"
)

func capture(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}

	return b
}

func TestProtocolFixture(t *testing.T) {
	request, err := groupRequest(fixtureGroup)
	if err != nil {
		t.Fatal(err)
	}

	for _, fixture := range []struct {
		data []byte
		hex  string
	}{
		{loginRequest(), loginrequestHex},
		{request, grouprequestHex},
		{logoutRequest(), logoutrequestHex},
	} {
		if !bytes.Equal(fixture.data, capture(t, fixture.hex)) {
			t.Fatalf("unexpected wire bytes: %x", fixture.data)
		}
	}

	if err := checkLogin(capture(t, loginresponseHex)); err != nil {
		t.Fatal(err)
	}

	reply := capture(t, groupresponseHex)
	for port := 1; port+portStride <= maxPort; port++ {
		binary.BigEndian.PutUint16(reply[202:204], uint16(port))
		got, err := groupReply(reply, request)
		want := Target{"app.example.test", port, port + 100}
		if err != nil || got != want {
			t.Fatalf("port %d: got %v, %v", port, got, err)
		}
	}

	got, err := groupReply(reply, request)
	if err != nil {
		t.Fatal(err)
	}

	reply[206] = 'x'
	if got.Host != "app.example.test" {
		t.Fatal("resolved host aliases the wire response")
	}
}

func TestProtocolRejectsMalformedReplies(t *testing.T) {
	for _, group := range []string{"", strings.Repeat("A", 41), "bad\x00group", "grüppe"} {
		if _, err := groupRequest(group); !errors.Is(err, ErrOptions) {
			t.Fatalf("invalid group %q: %v", group, err)
		}
	}

	login := capture(t, loginresponseHex)
	for _, offset := range []int{0, 12, 13, 57, 66, 67} {
		reply := bytes.Clone(login)
		reply[offset] ^= 0xff
		if err := checkLogin(reply); err == nil {
			t.Fatalf("login mutation %d was accepted", offset)
		}
	}

	for _, length := range []int{0, len(login) - 1, len(login) + 1} {
		if err := checkLogin(append(bytes.Clone(login), 0)[:length]); err == nil {
			t.Fatalf("login length %d was accepted", length)
		}
	}

	request := capture(t, grouprequestHex)
	valid := capture(t, groupresponseHex)
	for _, offset := range []int{66, 67, 110, 112, 113, 157, 158, 198, 199, 200, 204, 205, 206, len(valid) - 1} {
		reply := bytes.Clone(valid)
		reply[offset] ^= 0xff
		if _, err := groupReply(reply, request); !errors.Is(err, ErrProtocol) {
			t.Fatalf("group mutation %d: %v", offset, err)
		}
	}

	for _, length := range []int{0, headerLength, 114, len(valid) - 1, len(valid) + 1} {
		if _, err := groupReply(append(bytes.Clone(valid), 0)[:length], request); !errors.Is(err, ErrProtocol) {
			t.Fatalf("group reply length %d: %v", length, err)
		}
	}

	for _, port := range []uint16{0, maxPort} {
		reply := bytes.Clone(valid)
		binary.BigEndian.PutUint16(reply[202:204], port)
		if _, err := groupReply(reply, request); !errors.Is(err, ErrProtocol) {
			t.Fatalf("dispatcher port %d: %v", port, err)
		}
	}

	server := bytes.Clone(valid[:110])
	server[13] = 84
	opcode := bytes.Clone(valid[:114])
	opcode[111] = 5
	for _, reply := range [][]byte{server, opcode} {
		if _, err := groupReply(reply, request); !errors.Is(err, ErrRejected) {
			t.Fatalf("negative group reply: %v", err)
		}
	}

	other, _ := groupRequest("OTHER")
	if _, err := groupReply(valid, other); !errors.Is(err, ErrProtocol) {
		t.Fatalf("mismatched group echo: %v", err)
	}
}

func FuzzGroupReply(f *testing.F) {
	f.Add(capture(f, groupresponseHex))
	f.Add([]byte{})
	request := capture(f, grouprequestHex)
	f.Fuzz(func(t *testing.T, b []byte) {
		target, err := groupReply(b, request)
		if err == nil && (target.Host == "" || target.GatewayPort != target.DispatcherPort+100 || target.GatewayPort > maxPort) {
			t.Fatalf("unusable target: %+v", target)
		}
	})
}
