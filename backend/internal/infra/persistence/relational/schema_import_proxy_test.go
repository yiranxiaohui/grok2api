package relational

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitializeSchemaSupportsStrictImportProxyBindings(t *testing.T) {
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "strict-import-proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	definition, err := database.constraintDefinition(ctx, consoleConstraint{
		model: &accountModel{}, table: "provider_accounts", name: "chk_accounts_egress_assignment_mode",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(definition, "strict") {
		t.Fatalf("egress assignment constraint = %s", definition)
	}
	assertTableColumns(t, database, "egress_nodes", []string{"import_only", "import_fingerprint"}, nil)
	assertSQLiteUniqueIndexes(t, database, "egress_nodes", "uidx_egress_nodes_import_fingerprint")
	assertSQLiteIndexes(t, database, "egress_nodes", "idx_egress_nodes_import_only")
}
