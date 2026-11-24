// SPDX-License-Identifier: Apache-2.0
// Ported from open-rfc src/transport/message-server-resolver.ts at 847036d, Copyright 2026 Marian Zeis.

package msgserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ad3n/open-rfc-go/internal/saprouter"
	"github.com/ad3n/open-rfc-go/internal/transport"
)

type Options struct {
	Proxy    transport.ContextDialer
	Host     string
	Service  string
	SystemID string
	Group    string
	Router   string
	Timeout  time.Duration
}

func Resolve(ctx context.Context, opts Options) (_ Target, err error) {
	if !printable(opts.Host, 255, '!') || !systemID(opts.SystemID) || opts.Timeout < 0 {
		return Target{}, fmt.Errorf("%w: host, three-character system ID and nonnegative timeout are required", ErrOptions)
	}

	request, err := groupRequest(opts.Group)
	if err != nil {
		return Target{}, err
	}

	service := opts.Service
	if service == "" {
		service = "sapms" + opts.SystemID
	}

	if !printable(service, 64, '!') || strings.ContainsRune(service, '/') {
		return Target{}, fmt.Errorf("%w: invalid TCP service", ErrOptions)
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	port, err := net.DefaultResolver.LookupPort(ctx, "tcp", service)
	if err != nil {
		return Target{}, fmt.Errorf("message server service %q: %w", service, err)
	}

	if port < 1 || port > maxPort {
		return Target{}, fmt.Errorf("%w: service port must be in 1..65535", ErrOptions)
	}

	dial := transport.DialOptions{
		Options: transport.Options{MaxPayloadLength: maxPayload, ReadTimeout: timeout, WriteTimeout: timeout},
		Proxy:   opts.Proxy,
	}
	if opts.Router != "" {
		dial.Router, err = saprouter.CompleteRoute(opts.Router, opts.Host, port)
		if err != nil {
			return Target{}, fmt.Errorf("%w: %w", ErrOptions, err)
		}
	}

	conn, err := transport.DialWith(ctx, "tcp", net.JoinHostPort(opts.Host, strconv.Itoa(port)), dial)
	if err != nil {
		return Target{}, err
	}

	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer func() {
		stop()
		closeErr := conn.Close()
		if cause := ctx.Err(); cause != nil {
			err = cause
		}

		if err == nil && !errors.Is(closeErr, net.ErrClosed) {
			err = closeErr
		}
	}()

	if err := conn.Send(loginRequest()); err != nil {
		return Target{}, err
	}

	reply, err := conn.Receive(ctx)
	if err != nil {
		return Target{}, err
	}

	if err := checkLogin(reply); err != nil {
		return Target{}, err
	}

	if err := conn.Send(request); err != nil {
		return Target{}, err
	}

	reply, err = conn.Receive(ctx)
	if err != nil {
		return Target{}, err
	}

	defer func() {
		if ctx.Err() == nil {
			err = errors.Join(err, conn.Send(logoutRequest()))
		}
	}()

	return groupReply(reply, request)
}

func systemID(s string) bool {
	if len(s) != 3 {
		return false
	}

	for _, c := range s {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}

	return true
}
