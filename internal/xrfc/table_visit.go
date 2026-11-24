// SPDX-License-Identifier: Apache-2.0

package xrfc

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/ad3n/open-rfc-go/internal/metadata"
	"github.com/ad3n/open-rfc-go/internal/rfctypes"
)

func tableRowCount(text, name string, maxRows int) (uint, error) {
	decoder := xml.NewDecoder(strings.NewReader(text))
	var depth, count int
	for {
		token, err := decoder.Token()
		if err != nil {
			if err == io.EOF && depth == 0 {
				return uint(count), nil
			}

			return 0, fmt.Errorf("%w: %s invalid XML table: %v", ErrProtocol, name, err)
		}

		switch t := token.(type) {
		case xml.StartElement:
			if depth == 1 {
				if t.Name.Local != "item" {
					return 0, fmt.Errorf("%w: %s expected a table row", ErrProtocol, name)
				}

				count++
				if count > maxRows {
					return 0, fmt.Errorf("%w: %s row count exceeds %d", ErrRange, name, maxRows)
				}
			}

			depth++
		case xml.EndElement:
			depth--
		}
	}
}

func VisitTable(name string, def rfctypes.RfcStructureDefinition, data []byte, limits Limits, limit uint, visit func(uint, map[string]any) error) error {
	if err := AssertXMLName(name, "xRFC parameter name"); err != nil {
		return err
	}

	def, err := normalizeDefinition(def)
	if err != nil {
		return err
	}

	norm, err := NormalizeLimits(limits)
	if err != nil {
		return err
	}

	text, err := snapshotAndValidate(name, data, norm)
	if err != nil {
		return err
	}

	total, err := tableRowCount(text, name, norm.MaxRows)
	if err != nil {
		return err
	}

	p := &parser{text: text, limits: norm}
	if err := p.open(name); err != nil {
		return err
	}

	budget := &decodeBudget{limits: norm}
	for i := range total {
		row, err := parseRow(p, def, norm, true, budget)
		if err != nil {
			return err
		}

		if limit == 0 || i < limit {
			if err := visit(total, row); err != nil {
				return err
			}
		}
	}

	if err := p.close(name); err != nil {
		return err
	}

	return p.finish()
}

func VisitRecursiveTable(parameter FunintParameter, graph metadata.Graph, data []byte, limits RecursiveLimits, limit uint, visit func(uint, any) error) error {
	norm, err := normalizeRecursiveLimits(limits)
	if err != nil {
		return err
	}

	resolved, err := validateAtDepth(graph, parameter, norm.maxDepth, nil)
	if err != nil {
		return err
	}

	name := parameter.ParameterName
	if resolved.Kind != KindTable || len(data) > norm.maxParameterBytes {
		return fmt.Errorf("%w: %s is not a bounded recursive xRFC table", ErrRange, name)
	}

	text, err := decodeUTF8(data, name+" recursive xRFC XML")
	if err != nil {
		return err
	}

	total, err := tableRowCount(text, name, norm.maxRows)
	if err != nil {
		return err
	}

	p := &rparser{text: text, limits: norm}
	if err := p.open(name, name); err != nil {
		return err
	}

	if err := walkTable(graph, resolved.Node, p, norm, 1, name, func(i uint, row any) error {
		if limit == 0 || i < limit {
			return visit(total, row)
		}

		return nil
	}); err != nil {
		return err
	}

	if err := p.close(name, name); err != nil {
		return err
	}

	return p.finish()
}
