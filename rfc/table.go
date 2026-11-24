// SPDX-License-Identifier: Apache-2.0

package rfc

import (
	"context"
	"errors"
	"fmt"

	"github.com/ad3n/open-rfc-go/internal/classicrfc"
	"github.com/ad3n/open-rfc-go/internal/structure"
	"github.com/ad3n/open-rfc-go/internal/xrfc"
)

type tableVisitor func(uint, map[string]any) error

// CallTable invokes a function and decodes only the selected table's rows.
// A zero limit visits every row. Each callback owns its row and receives the
// total row count before limiting. The response bytes are buffered by CPIC.
func (c *Client) CallTable(ctx context.Context, functionName string, in Params, key string, limit uint, visit func(uint, map[string]any) error) error {
	if visit == nil || key == "" {
		return fmt.Errorf("%w: table name and visitor are required", ErrInvalidParameter)
	}

	lease, err := c.pool.Acquire(ctx)
	if err != nil {
		return translate(err)
	}
	defer lease.Release()

	response, err := c.exchangeCall(ctx, lease.Value(), functionName, in)
	if err != nil {
		if errors.Is(err, ErrTransport) {
			lease.Discard()
		}

		return err
	}

	read, err := response.tableReader(key)
	if err != nil {
		if errors.Is(err, ErrTransport) {
			lease.Discard()
		}

		return err
	}

	lease.Release()
	return read(limit, func(total uint, row map[string]any) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		return visit(total, row)
	})
}

func (r callResponse) tableReader(key string) (func(uint, tableVisitor) error, error) {
	var p classicrfc.FunintParameter
	for _, parameter := range r.iface.Parameters {
		if parameter.ParameterName == key {
			p = parameter
			break
		}
	}

	if p.ParameterName == "" || p.ParameterClass == "I" {
		return nil, fmt.Errorf("%w: output table %s", ErrUnknownParameter, key)
	}

	if p.ParameterClass != "T" && !isTableExid(p.Exid) {
		return nil, fmt.Errorf("%w: output %s is not a table", ErrInvalidParameter, key)
	}

	classic, xml, err := classicrfc.DecodeOwnedTable(r.fields, key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProtocol, err)
	}

	if classic.Found {
		def, err := r.resolve(p.TableName)
		if err != nil {
			return nil, err
		}

		return func(limit uint, visit tableVisitor) error {
			var codec *structure.FixedCodec
			return classic.Visit(limit, func(total uint, raw []byte) error {
				if codec == nil {
					compiled, err := structure.NewFixedCodec(def)
					if err != nil {
						return fmt.Errorf("%w: %s: %w", ErrProtocol, key, err)
					}

					codec = &compiled
				}

				row, err := codec.Decode(padTrailingFill(def, raw))
				if err != nil {
					return fmt.Errorf("%w: %s: %w", ErrProtocol, key, err)
				}

				return visit(total, row)
			})
		}, nil
	}

	for _, parameter := range xml {
		name, err := xrfc.DecodeParameterName(parameter.Value, xrfc.Limits{})
		if err != nil {
			return nil, fmt.Errorf("%w: xRFC parameter name: %w", ErrProtocol, err)
		}

		if name != key {
			continue
		}

		if rp, ok := r.plan.lookup(key); ok && rp.Kind == xrfc.KindTable {
			return func(limit uint, visit tableVisitor) error {
				return xrfc.VisitRecursiveTable(p, r.plan.graph, parameter.Value, xrfc.RecursiveLimits{}, limit, func(total uint, value any) error {
					row, ok := normalizeGraphValue(value).(map[string]any)
					if !ok {
						row = map[string]any{"": value}
					}

					return visit(total, row)
				})
			}, nil
		}

		def, err := r.resolve(p.TableName)
		if err != nil {
			return nil, err
		}

		return func(limit uint, visit tableVisitor) error {
			return xrfc.VisitTable(key, def, parameter.Value, xrfc.Limits{}, limit, visit)
		}, nil
	}

	if classic.Positional {
		return nil, fmt.Errorf("%w: cannot identify output %s in positional tables", ErrProtocol, key)
	}

	return func(uint, tableVisitor) error { return nil }, nil
}
