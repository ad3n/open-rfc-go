// SPDX-License-Identifier: Apache-2.0
// Loopback exchange tests adapted from open-rfc test/message-server-resolver.test.ts at 847036d, Copyright 2026 Marian Zeis.

package msgserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/ad3n/open-rfc-go/internal/transport"
	"github.com/ad3n/open-rfc-go/ni"
)

func TestResolveLoopback(t *testing.T) {
	for _, scenario := range []string{"success", "eof", "oversize", "timeout", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			login := capture(t, loginresponseHex)
			group := capture(t, groupresponseHex)
			serveErr := make(chan error, 1)
			go func() {
				serveErr <- serveFixture(listener, scenario, login, group, cancel)
			}()

			timeout := 2 * time.Second
			if scenario == "timeout" {
				timeout = 200 * time.Millisecond
			}

			target, err := Resolve(ctx, Options{Host: "127.0.0.1", Service: strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), SystemID: "DEV", Group: fixtureGroup, Timeout: timeout})
			switch scenario {
			case "success":
				if err != nil || target != (Target{"app.example.test", 3200, 3300}) {
					t.Fatalf("resolve: %+v, %v", target, err)
				}
			case "cancel":
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("resolve: %v, want canceled", err)
				}
			case "timeout":
				var networkErr net.Error
				if !errors.Is(err, context.DeadlineExceeded) && (!errors.As(err, &networkErr) || !networkErr.Timeout()) {
					t.Fatalf("resolve: %v, want timeout", err)
				}
			default:
				if err == nil {
					t.Fatal("resolve accepted an invalid exchange")
				}
			}

			if err := <-serveErr; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func serveFixture(listener net.Listener, scenario string, login, group []byte, cancel context.CancelFunc) error {
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()

	wire := transport.New(conn, transport.Options{ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second})
	ctx := context.Background()
	got, err := wire.Receive(ctx)
	if err != nil || !bytes.Equal(got, loginRequest()) {
		return fmt.Errorf("unexpected login: %x, %w", got, err)
	}

	if err := wire.Send(login); err != nil {
		return err
	}

	got, err = wire.Receive(ctx)
	want, _ := groupRequest(fixtureGroup)
	if err != nil || !bytes.Equal(got, want) {
		return fmt.Errorf("unexpected group query: %x, %w", got, err)
	}

	switch scenario {
	case "eof":
		return nil
	case "oversize":
		_, err = conn.Write([]byte{0, 0, 2, 1})
		return err
	case "cancel":
		cancel()
	case "success":
		frame, err := ni.EncodeFrame(group)
		if err != nil {
			return err
		}

		for _, piece := range [][]byte{frame[:3], frame[3:18], frame[18:]} {
			if _, err := conn.Write(piece); err != nil {
				return err
			}
		}

		got, err := wire.Receive(ctx)
		if err != nil || !bytes.Equal(got, logoutRequest()) {
			return fmt.Errorf("unexpected logout: %x, %w", got, err)
		}
	}

	_, err = wire.Receive(ctx)
	if !errors.Is(err, transport.ErrClosed) {
		return fmt.Errorf("expected resolver to close: %v", err)
	}

	return nil
}

func TestResolveRejectsInvalidOptions(t *testing.T) {
	for _, opts := range []Options{
		{},
		{Host: "127.0.0.1", SystemID: "A", Group: fixtureGroup},
		{Host: "127.0.0.1", SystemID: "DEV", Group: fixtureGroup, Service: "tcp/3600"},
		{Host: "127.0.0.1", SystemID: "DEV", Group: fixtureGroup, Service: "0"},
		{Host: "127.0.0.1", SystemID: "DEV", Group: "\x00"},
	} {
		if _, err := Resolve(t.Context(), opts); !errors.Is(err, ErrOptions) {
			t.Fatalf("Resolve(%+v): %v", opts, err)
		}
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Resolve(ctx, Options{Host: "127.0.0.1", SystemID: "DEV", Group: fixtureGroup, Service: "3600"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Resolve: %v", err)
	}
}
