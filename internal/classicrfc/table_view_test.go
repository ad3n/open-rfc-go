// SPDX-License-Identifier: Apache-2.0

package classicrfc

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ad3n/open-rfc-go/internal/cpic"
)

func TestVisitOwnedTable(t *testing.T) {
	fields := []cpic.Field{
		fld(cpic.TagTableName, u16("IGNORE")),
		fld(cpic.TagTableHeader, tableHeaderBytes(4, 1)),
		fld(cpic.TagTableCompr, []byte{5}),
		fld(cpic.TagTableName, u16("ROWS")),
		fld(cpic.TagTableHeader, tableHeaderBytes(4, 2)),
		fld(cpic.TagTableCompr, []byte{1, 2}),
		fld(cpic.TagTableContent, []byte{3, 4, 5, 6}),
		fld(cpic.TagEnd, nil),
	}
	view, xml, err := DecodeOwnedTable(fields, "ROWS")
	if err != nil || !view.Found || len(xml) != 0 {
		t.Fatalf("unexpected selection: view=%+v, xml=%v, err=%v", view, xml, err)
	}

	count := 0
	stop := errors.New("stop")
	err = view.Visit(1, func(total uint, row []byte) error {
		count++
		if total != 2 || !bytes.Equal(row, []byte{1, 2, 2, 2}) {
			t.Fatalf("total=%d row=%v", total, row)
		}

		return stop
	})
	if !errors.Is(err, stop) || count != 1 {
		t.Fatalf("visitor: %d rows, %v", count, err)
	}

	fields[2].Value = nil
	if _, _, err := DecodeOwnedTable(fields, "ROWS"); err == nil {
		t.Fatal("ignored table framing was not validated")
	}
}

func FuzzDecodeOwnedTable(f *testing.F) {
	f.Add(uint32(1), []byte{42})
	f.Add(uint32(0xffffffff), []byte{})
	f.Fuzz(func(t *testing.T, rows uint32, data []byte) {
		view, _, err := DecodeOwnedTable([]cpic.Field{
			fld(cpic.TagTableName, u16("ROWS")),
			fld(cpic.TagTableHeader, tableHeaderBytes(4, rows)),
			fld(cpic.TagTableCompr, data),
		}, "ROWS")
		if err == nil {
			_ = view.Visit(1, func(uint, []byte) error { return nil })
		}
	})
}
