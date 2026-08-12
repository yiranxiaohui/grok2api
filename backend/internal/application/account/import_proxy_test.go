package account

import (
	"context"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	egressdomain "github.com/chenyme/grok2api/backend/internal/domain/egress"
	"github.com/chenyme/grok2api/backend/internal/infra/persistence/relational"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
	cliprovider "github.com/chenyme/grok2api/backend/internal/infra/provider/cli"
	"github.com/chenyme/grok2api/backend/internal/infra/security"
	"github.com/chenyme/grok2api/backend/internal/repository"
)

func newBuildProxyImportService(t *testing.T) (*Service, *relational.AccountRepository, *relational.EgressRepository, *security.Cipher) {
	t.Helper()
	ctx := context.Background()
	database, err := relational.OpenSQLite(ctx, filepath.Join(t.TempDir(), "proxy-import.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	cipher, err := security.NewCipher(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	accounts := relational.NewAccountRepository(database)
	egress := relational.NewEgressRepository(database)
	registry := provider.NewRegistry(cliprovider.NewAdapter(cliprovider.Config{}, cipher))
	return NewService(accounts, nil, nil, nil, registry, cipher, nil), accounts, egress, cipher
}

func TestBuildImportCreatesSharedStrictProxyBindingAndUpdatesIt(t *testing.T) {
	ctx := context.Background()
	service, accounts, egress, cipher := newBuildProxyImportService(t)
	firstProxy := "http://user:pass@first-proxy.example:8080"
	initial := []byte(`{"accounts":[` +
		`{"name":"first","refresh_token":"refresh-1","proxy_url":"` + firstProxy + `"},` +
		`{"name":"second","refresh_token":"refresh-2","proxy":"` + firstProxy + `"}` +
		`]}`)

	created, err := service.ImportCredentials(ctx, initial)
	if err != nil {
		t.Fatal(err)
	}
	if created.Created != 2 || len(created.AccountIDs) != 2 {
		t.Fatalf("created result = %#v", created)
	}
	first, err := accounts.Get(ctx, created.AccountIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	second, err := accounts.Get(ctx, created.AccountIDs[1])
	if err != nil {
		t.Fatal(err)
	}
	if first.EgressNodeID == 0 || first.EgressNodeID != second.EgressNodeID || first.EgressAssignmentMode != accountdomain.EgressAssignmentStrict || second.EgressAssignmentMode != accountdomain.EgressAssignmentStrict {
		t.Fatalf("strict bindings = %#v, %#v", first, second)
	}
	nodes, err := egress.ListEgressNodes(ctx, egressdomain.ScopeBuild, repository.SortQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || !nodes[0].ImportOnly || nodes[0].ID != first.EgressNodeID {
		t.Fatalf("import nodes = %#v", nodes)
	}
	decrypted, err := cipher.Decrypt(nodes[0].EncryptedProxyURL)
	if err != nil || decrypted != firstProxy {
		t.Fatalf("stored proxy = %q, err=%v", decrypted, err)
	}
	oldNodeID := nodes[0].ID

	secondProxy := "socks5h://user:pass@second-proxy.example:1080"
	updatedDocument := []byte(`{"accounts":[` +
		`{"name":"first","refresh_token":"refresh-1","proxy_url":"` + secondProxy + `"},` +
		`{"name":"second","refresh_token":"refresh-2","proxy_url":"` + secondProxy + `"}` +
		`]}`)
	updated, err := service.ImportCredentials(ctx, updatedDocument)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Updated != 2 {
		t.Fatalf("updated result = %#v", updated)
	}
	first, err = accounts.Get(ctx, created.AccountIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	second, err = accounts.Get(ctx, created.AccountIDs[1])
	if err != nil {
		t.Fatal(err)
	}
	if first.EgressNodeID == oldNodeID || first.EgressNodeID != second.EgressNodeID || first.EgressAssignmentMode != accountdomain.EgressAssignmentStrict {
		t.Fatalf("updated strict bindings = %#v, %#v", first, second)
	}
	nodes, err = egress.ListEgressNodes(ctx, egressdomain.ScopeBuild, repository.SortQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].ID != first.EgressNodeID {
		t.Fatalf("old imported node was not collected: %#v", nodes)
	}
	decrypted, err = cipher.Decrypt(nodes[0].EncryptedProxyURL)
	if err != nil || decrypted != secondProxy {
		t.Fatalf("updated stored proxy = %q, err=%v", decrypted, err)
	}

	// Omitting the proxy on a later credential refresh preserves the explicit
	// strict binding instead of clearing or downgrading it.
	if _, err := service.ImportCredentials(ctx, []byte(`{"refresh_token":"refresh-1"}`)); err != nil {
		t.Fatal(err)
	}
	first, err = accounts.Get(ctx, created.AccountIDs[0])
	if err != nil || first.EgressNodeID != nodes[0].ID || first.EgressAssignmentMode != accountdomain.EgressAssignmentStrict {
		t.Fatalf("binding after proxy-less reimport = %#v, err=%v", first, err)
	}
	if deleted, err := accounts.DeleteMany(ctx, created.AccountIDs); err != nil || deleted != 2 {
		t.Fatalf("delete imported accounts = %d, err=%v", deleted, err)
	}
	nodes, err = egress.ListEgressNodes(ctx, egressdomain.ScopeBuild, repository.SortQuery{})
	if err != nil || len(nodes) != 0 {
		t.Fatalf("orphan imported proxies after account deletion = %#v, err=%v", nodes, err)
	}
}

func TestImportRejectsInvalidProxyBeforeWritingAnyAccounts(t *testing.T) {
	ctx := context.Background()
	service, accounts, egress, _ := newBuildProxyImportService(t)
	document := []byte(`{"accounts":[` +
		`{"refresh_token":"valid-account","proxy_url":"http://proxy.example:8080"},` +
		`{"refresh_token":"invalid-account","proxy_url":"file:///tmp/not-a-proxy"}` +
		`]}`)

	_, err := service.ImportCredentials(ctx, document)
	if !errors.Is(err, ErrInvalidImport) {
		t.Fatalf("invalid proxy error = %v", err)
	}
	_, total, listErr := accounts.List(ctx, repository.AccountListQuery{
		Page: repository.PageQuery{Limit: 1}, Filter: repository.AccountListFilter{Provider: string(accountdomain.ProviderBuild)},
	})
	if listErr != nil {
		t.Fatal(listErr)
	}
	if total != 0 {
		t.Fatalf("accounts persisted after invalid proxy = %d", total)
	}
	nodes, listErr := egress.ListEgressNodes(ctx, egressdomain.ScopeBuild, repository.SortQuery{})
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(nodes) != 0 {
		t.Fatalf("nodes persisted after invalid proxy = %#v", nodes)
	}
}

func TestBuildImportDuplicateAccountKeepsFirstProxyWithoutOrphans(t *testing.T) {
	ctx := context.Background()
	service, accounts, egress, cipher := newBuildProxyImportService(t)
	document := []byte(`{"accounts":[` +
		`{"refresh_token":"same-account","proxy_url":"http://first.example:8080"},` +
		`{"refresh_token":"same-account","proxy_url":"http://last.example:8080"}` +
		`]}`)

	result, err := service.ImportCredentials(ctx, document)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.AccountIDs) != 1 || result.Created != 1 {
		t.Fatalf("duplicate import result = %#v", result)
	}
	credential, err := accounts.Get(ctx, result.AccountIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := egress.ListEgressNodes(ctx, egressdomain.ScopeBuild, repository.SortQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].ID != credential.EgressNodeID {
		t.Fatalf("duplicate import nodes = %#v, credential = %#v", nodes, credential)
	}
	proxyURL, err := cipher.Decrypt(nodes[0].EncryptedProxyURL)
	if err != nil || proxyURL != "http://first.example:8080" {
		t.Fatalf("deduplicated proxy = %q, err=%v", proxyURL, err)
	}
}
