// SPDX-License-Identifier: Apache-2.0

package mockbridge

import (
	"net"

	"github.com/ad3n/open-rfc-go/internal/cpic"
	"github.com/ad3n/open-rfc-go/internal/rfcserver"
)

type (
	Request    = rfcserver.Request
	Response   = rfcserver.Response
	Table      = rfcserver.Table
	NamedValue = cpic.NamedValue
	Output     = rfcserver.Output
	Exception  = rfcserver.Exception
	Handler    = rfcserver.Handler
	Dispatcher = rfcserver.Dispatcher
)

func NewDispatcher() *Dispatcher { return rfcserver.NewDispatcher() }

func Serve(conn net.Conn, dispatcher *Dispatcher, log func(string)) {
	rfcserver.ServeConscious(conn, dispatcher, log, nil)
}

func DFIESRow(values map[string]string) ([]byte, error) {
	return rfcserver.MockDFIESRow(values)
}

func TypeHeader(name string, length, count int, unicodeLength byte) ([]byte, error) {
	return rfcserver.MockTypeHeader(name, length, count, unicodeLength)
}
