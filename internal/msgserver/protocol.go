// SPDX-License-Identifier: Apache-2.0
// Ported from open-rfc src/protocol/message-server.ts at 847036d, Copyright 2026 Marian Zeis.

package msgserver

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	headerLength  = 110
	requestLength = 206
	maxPayload    = 512
	messageMagic  = "**MESSAGE**\x00"
	serverName    = "MSG_SERVER"
	nameLength    = 40
	portStride    = 100
	maxPort       = 65535
	groupOpcode   = 0x2c
	groupVersion  = 1
	logonSelector = 0x34
)

var (
	ErrOptions  = errors.New("message server: invalid options")
	ErrProtocol = errors.New("message server: invalid reply")
	ErrRejected = errors.New("message server: rejected request")
)

type Target struct {
	Host           string
	DispatcherPort int
	GatewayPort    int
}

func header(size int, to, from string, toPad, fromPad, reserved, flag, iface byte) []byte {
	b := make([]byte, size)
	copy(b, messageMagic)
	b[12] = 4
	padName(b[14:54], to, toPad)
	b[57], b[66], b[67] = reserved, flag, iface
	padName(b[68:108], from, fromPad)
	return b
}

func padName(dst []byte, name string, pad byte) {
	for i := range dst {
		dst[i] = pad
	}

	copy(dst, name)
}

func loginRequest() []byte { return header(headerLength, "-", "-", 0, ' ', 0, 2, 8) }

func logoutRequest() []byte { return header(headerLength, "-", "-", 0, ' ', 0, 0, 4) }

func groupRequest(group string) ([]byte, error) {
	if !printable(group, nameLength, ' ') {
		return nil, fmt.Errorf("%w: group must be 1..40 printable ASCII bytes", ErrOptions)
	}

	b := header(requestLength, serverName, "-", 0, ' ', 0, 2, 1)
	b[110], b[112] = groupOpcode, groupVersion
	binary.BigEndian.PutUint32(b[154:158], uint32(len(group)+4))
	copy(b[158:198], group)
	b[198] = 1
	binary.BigEndian.PutUint16(b[202:204], logonSelector)
	return b, nil
}

func matchHeader(b, expected []byte) error {
	if len(b) < headerLength || !bytes.Equal(b[:13], expected[:13]) || !bytes.Equal(b[14:headerLength], expected[14:]) {
		return fmt.Errorf("%w: unexpected header", ErrProtocol)
	}

	if b[13] != 0 {
		return fmt.Errorf("%w: server error %d", ErrRejected, b[13])
	}

	return nil
}

func checkLogin(b []byte) error {
	if len(b) != headerLength {
		return fmt.Errorf("%w: unexpected login reply length", ErrProtocol)
	}

	return matchHeader(b, header(headerLength, "-", serverName, ' ', ' ', 1, 2, 8))
}

func groupReply(b, request []byte) (Target, error) {
	if len(b) > maxPayload {
		return Target{}, fmt.Errorf("%w: reply exceeds %d bytes", ErrProtocol, maxPayload)
	}

	if err := matchHeader(b, header(headerLength, "-", serverName, ' ', 0, 0, 3, 1)); err != nil {
		return Target{}, err
	}

	if len(b) < 114 || b[110] != groupOpcode || b[112] != groupVersion || b[113] != 3 {
		return Target{}, fmt.Errorf("%w: unexpected group opcode, version or charset", ErrProtocol)
	}

	if b[111] != 0 {
		return Target{}, fmt.Errorf("%w: group opcode error %d", ErrRejected, b[111])
	}

	if len(b) < requestLength+1 || !bytes.Equal(b[114:202], request[114:202]) {
		return Target{}, fmt.Errorf("%w: unexpected group echo or result header", ErrProtocol)
	}

	port := int(binary.BigEndian.Uint16(b[202:204]))
	hostLength := int(binary.BigEndian.Uint16(b[204:206]))
	if port < 1 || port+portStride > maxPort || len(b) != requestLength+hostLength+1 {
		return Target{}, fmt.Errorf("%w: invalid dispatcher port or target length", ErrProtocol)
	}

	host := string(b[requestLength : len(b)-1])
	if !printable(host, 255, '!') || b[len(b)-1] != ' ' {
		return Target{}, fmt.Errorf("%w: invalid target host or trailer", ErrProtocol)
	}

	return Target{Host: host, DispatcherPort: port, GatewayPort: port + portStride}, nil
}

func printable(s string, limit int, low byte) bool {
	if len(s) == 0 || len(s) > limit {
		return false
	}

	for i := range len(s) {
		if s[i] < low || s[i] > '~' {
			return false
		}
	}

	return true
}
