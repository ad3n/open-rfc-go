// SPDX-License-Identifier: Apache-2.0

package classicrfc

import "github.com/ad3n/open-rfc-go/internal/cpic"

type TableView struct {
	name       string
	fields     []cpic.Field
	width      uint32
	Found      bool
	Positional bool
}

func DecodeOwnedTable(fields []cpic.Field, name string) (TableView, []XrfcParameter, error) {
	view := TableView{name: name}
	result, err := decodeResult(fields, true, &view)
	return view, result.XrfcParameters, err
}

func (t TableView) Visit(limit uint, visit func(total uint, row []byte) error) error {
	total := uint(len(t.fields))
	count := total
	if limit > 0 {
		count = min(count, limit)
	}

	for i, field := range t.fields[:count] {
		row := field.Value
		if field.Tag == uint16(cpic.TagTableCompr) {
			decoded, err := decodeSimpleCompressedTableRow(row, t.width, t.name, i, true)
			if err != nil {
				return err
			}

			row = decoded
		}

		if err := visit(total, row); err != nil {
			return err
		}
	}

	return nil
}
