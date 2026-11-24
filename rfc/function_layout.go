// SPDX-License-Identifier: Apache-2.0

package rfc

import (
	"context"
	"fmt"

	"github.com/ad3n/open-rfc-go/internal/metadata"
	"github.com/ad3n/open-rfc-go/internal/rfctypes"
	"github.com/ad3n/open-rfc-go/internal/xrfc"
)

type (
	FunctionLayout struct {
		Name       string
		Parameters []ParameterLayout
	}

	ParameterLayout struct {
		Direction string
		Text      string
		FieldLayout
		Optional bool
	}

	FieldLayout struct {
		Name     string
		Exid     string
		Fields   []FieldLayout
		Length   int
		Decimals int
	}
)

func (c *Client) FunctionLayout(ctx context.Context, name string) (FunctionLayout, error) {
	lease, err := c.pool.Acquire(ctx)
	if err != nil {
		return FunctionLayout{}, translate(err)
	}
	defer lease.Release()

	session := lease.Value()
	iface, err := c.functionInterfaceOn(ctx, session, name)
	if err != nil {
		return FunctionLayout{}, err
	}

	resolve := func(name string) (rfctypes.RfcStructureDefinition, error) {
		return c.structureDefinitionOn(ctx, session, name)
	}
	plan := c.planLayoutOn(ctx, session, iface, resolve)
	result := FunctionLayout{Name: iface.Name, Parameters: make([]ParameterLayout, 0, len(iface.Parameters))}
	for _, p := range iface.Parameters {
		field := FieldLayout{Name: p.ParameterName, Exid: p.Exid, Length: int(p.InternalLength), Decimals: int(p.Decimals)}
		if p.ParameterClass == "T" {
			field.Exid = "h"
		}

		switch resolved, recursive := plan.lookup(p.ParameterName); {
		case recursive:
			field.Length = resolved.Node.NucLength
			if resolved.Kind == xrfc.KindTable {
				field.Exid = "h"
			}

			field.Fields = graphFieldLayout(plan.graph, resolved.Node, 0)
		case paramHasLayout(p):
			def, err := resolve(p.TableName)
			if err != nil {
				return FunctionLayout{}, fmt.Errorf("%s: %w", p.ParameterName, err)
			}

			field.Fields = make([]FieldLayout, 0, len(def.Fields))
			for _, child := range def.Fields {
				length := int(child.InternalLength)
				if child.Exid == "C" || child.Exid == "N" || child.Exid == "D" || child.Exid == "T" {
					length /= 2
				}

				field.Fields = append(field.Fields, FieldLayout{Name: child.FieldName, Exid: child.Exid, Length: length, Decimals: int(child.Decimals)})
			}
		}

		result.Parameters = append(result.Parameters, ParameterLayout{FieldLayout: field, Direction: p.ParameterClass, Text: p.ParameterText, Optional: p.Optional})
	}

	return result, nil
}

func graphFieldLayout(graph metadata.Graph, node metadata.TypeNode, depth int) []FieldLayout {
	if depth >= maxGraphSchemaDepth {
		return nil
	}

	fields := make([]FieldLayout, 0, len(node.Fields))
	for _, field := range node.Fields {
		value := FieldLayout{Name: field.Name, Exid: field.InternalType, Length: field.NucLength, Decimals: field.Decimals}
		if field.Reference.Kind != "scalar" && !field.Reference.Cyclic {
			value.Fields = graphFieldLayout(graph, graph.Nodes[field.Reference.TargetType], depth+1)
		}

		fields = append(fields, value)
	}

	return fields
}
