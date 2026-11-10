package api

import (
	"encoding/json"
	"testing"
)

func TestLastGapSchemaMatchesNullableWireValue(t *testing.T) {
	raw, err := Schema()
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Components struct {
			Schemas map[string]struct{ Properties map[string]json.RawMessage }
		}
	}
	if err = json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	var gap struct {
		AnyOf []struct {
			Ref  string `json:"$ref"`
			Type string
		}
	}
	if err = json.Unmarshal(spec.Components.Schemas["SensorStatus"].Properties["last_gap"], &gap); err != nil {
		t.Fatal(err)
	}
	if len(gap.AnyOf) != 2 || gap.AnyOf[0].Ref != "#/components/schemas/CollectionGapIncident" || gap.AnyOf[1].Type != "null" {
		t.Fatalf("last_gap must accept an incident or null: %+v", gap)
	}
}
