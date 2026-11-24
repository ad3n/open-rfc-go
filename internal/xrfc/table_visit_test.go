// SPDX-License-Identifier: Apache-2.0

package xrfc

import (
	"errors"
	"testing"

	"github.com/ad3n/open-rfc-go/internal/classicrfc"
	"github.com/ad3n/open-rfc-go/internal/metadata"
)

func TestVisitTable(t *testing.T) {
	const data = "<T><item><I>1</I><C>A</C><STR>&#60;item></STR><XSTR></XSTR></item><item><I>2</I><C>B</C><STR></STR><XSTR></XSTR></item></T>"
	var count int
	err := VisitTable("T", stfcRow(), []byte(data), Limits{}, 1, func(total uint, row map[string]any) error {
		count++
		if total != 2 || row["I"] != int32(1) || row["STR"] != "<item>" {
			t.Fatalf("total=%d, row=%v", total, row)
		}

		return nil
	})
	if err != nil || count != 1 {
		t.Fatalf("visit: %d rows, %v", count, err)
	}
}

func TestVisitRecursiveTable(t *testing.T) {
	const name = "ROWS"
	p := classicrfc.FunintParameter{ParameterClass: "T", ParameterName: name, TableName: "Z_TAB", Exid: "h"}
	g := graphOf("RFC_TEST", []metadata.Parameter{param("RFC_TEST", name, "T", "h", "Z_TAB", "table", "Z_TAB")},
		tnode("Z_TAB", rfield("", "u", "structure", "Z_ROW", 1, false)),
		snode("Z_ROW", sfield("N", "I", 1, 4, 0)))
	data := []byte("<ROWS><item><N>5</N></item><item><N>-1</N></item></ROWS>")
	stop := errors.New("done")
	count := 0
	err := VisitRecursiveTable(p, g, data, RecursiveLimits{}, 0, func(total uint, value any) error {
		count++
		row, ok := value.(map[string]any)
		if total != 2 || !ok || row["N"] != int32(5) {
			t.Fatalf("total=%d, row=%v", total, value)
		}

		return stop
	})
	if !errors.Is(err, stop) || count != 1 {
		t.Fatalf("visit: %d rows, %v", count, err)
	}
}
