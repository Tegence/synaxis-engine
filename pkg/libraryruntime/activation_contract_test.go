package libraryruntime

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestActivationBundleV1SchemaAndFixtures(t *testing.T) {
	t.Parallel()

	compiler := jsonschema.NewCompiler()
	schemaPath := "activation-bundle.v1.schema.json"
	schema, err := compiler.Compile(schemaPath)
	if err != nil {
		t.Fatalf("compile activation JSON Schema: %v", err)
	}

	fixtures := []struct {
		name         string
		schemaValid  bool
		adapterValid bool
	}{
		{name: "activation-bundle.v1.valid.json", schemaValid: true, adapterValid: true},
		{name: "activation-bundle.v1.invalid-unknown-field.json", schemaValid: false, adapterValid: false},
		{name: "activation-bundle.v1.invalid-tampered-instructions.json", schemaValid: true, adapterValid: false},
	}
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", fixture.name))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("decode fixture for JSON Schema: %v", err)
			}
			schemaErr := schema.Validate(instance)
			if got := schemaErr == nil; got != fixture.schemaValid {
				t.Fatalf("schema valid=%t, want %t (error: %v)", got, fixture.schemaValid, schemaErr)
			}
			_, adapterErr := DecodeAndVerifyActivationBundle(bytes.NewReader(raw), Limits{})
			if got := adapterErr == nil; got != fixture.adapterValid {
				t.Fatalf("adapter valid=%t, want %t (error: %v)", got, fixture.adapterValid, adapterErr)
			}
		})
	}
}
