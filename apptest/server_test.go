package apptest_test

import (
	"testing"

	"github.com/appwrite/sdk-for-go/query"
	"github.com/appwrite/sdk-for-go/tablesdb"
	"github.com/open-runtimes/types-for-go/v4/openruntimes"

	"github.com/ModdingFriendly/appwrite-library/apptest"
	"github.com/ModdingFriendly/appwrite-library/appwrite"
	"github.com/ModdingFriendly/appwrite-library/auth"
)

func serverCtx(s *apptest.Server) openruntimes.Context {
	ctx := openruntimes.Context{}
	ctx.Req.Headers = map[string]string{"x-appwrite-key": s.APIKey}
	return ctx
}

func tables(t *testing.T, s *apptest.Server) *tablesdb.TablesDB {
	t.Helper()
	tdb, err := appwrite.NewTables(appwrite.ConfigFromEnv(serverCtx(s)))
	if err != nil {
		t.Fatal(err)
	}
	return tdb
}

func TestJWTLookupResolvesUserAndMembership(t *testing.T) {
	s := apptest.New(t)
	s.Env(t)
	jwt := s.AddUser(apptest.User{ID: "u1", Name: "Ann"})
	s.AddMembership(apptest.Membership{TeamID: "team-a", UserID: "u1", Roles: []string{"admin"}, Confirmed: true})
	s.AddUser(apptest.User{ID: "u2"})
	s.AddMembership(apptest.Membership{TeamID: "team-b", UserID: "u2", Roles: []string{"admin"}, Confirmed: true})

	lookup, err := auth.NewJWTLookupFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	ctx := openruntimes.Context{}
	ctx.Req.Headers = map[string]string{auth.JWTHeader: jwt}
	id, err := lookup.CurrentUser(ctx)
	if err != nil || id.UserID != "u1" || id.Name != "Ann" {
		t.Fatalf("CurrentUser = %+v, %v", id, err)
	}
	m, err := lookup.Membership(ctx, "team-a", "u1")
	if err != nil || !m.Confirmed || m.Roles[0] != "admin" {
		t.Fatalf("Membership = %+v, %v", m, err)
	}
	if _, err := lookup.Membership(ctx, "team-b", "u1"); err == nil {
		t.Fatal("a user must not see another team's memberships")
	}
}

func TestRowsCRUDAndQueries(t *testing.T) {
	s := apptest.New(t)
	s.Env(t)
	s.Seed("tickets", "t1", map[string]any{"organization_id": "a", "status": "open", "total": 5})
	s.Seed("tickets", "t2", map[string]any{"organization_id": "b", "status": "open", "total": 9})
	s.Seed("tickets", "t3", map[string]any{"organization_id": "a", "status": "closed", "total": 7, "tags": []any{"x", "y"}})
	tdb := tables(t, s)

	list, err := tdb.ListRows(s.DatabaseID, "tickets", tdb.WithListRowsQueries([]string{
		query.Equal("organization_id", "a"), query.OrderDesc("total"), query.Limit(1),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if list.Total != 2 || len(list.Rows) != 1 || list.Rows[0].Id != "t3" {
		t.Fatalf("list = total %d, %+v", list.Total, list.Rows)
	}
	list, err = tdb.ListRows(s.DatabaseID, "tickets", tdb.WithListRowsQueries([]string{
		query.Or([]string{query.Equal("status", "closed"), query.GreaterThan("total", 8)}),
		query.CursorAfter("t2"),
	}))
	if err != nil || len(list.Rows) != 1 || list.Rows[0].Id != "t3" {
		t.Fatalf("or+cursor = %+v, %v", list, err)
	}
	list, err = tdb.ListRows(s.DatabaseID, "tickets", tdb.WithListRowsQueries([]string{query.Equal("tags", "y")}))
	if err != nil || len(list.Rows) != 1 {
		t.Fatalf("array equal = %+v, %v", list, err)
	}

	created, err := tdb.CreateRow(s.DatabaseID, "tickets", "unique()", map[string]any{"organization_id": "a"})
	if err != nil || created.Id == "" {
		t.Fatalf("create = %+v, %v", created, err)
	}
	if _, err := tdb.UpdateRow(s.DatabaseID, "tickets", "t1", tdb.WithUpdateRowData(map[string]any{"status": "done"})); err != nil {
		t.Fatal(err)
	}
	if row, _ := s.Row("tickets", "t1"); row["status"] != "done" {
		t.Fatalf("update not applied: %+v", row)
	}
	if _, err := tdb.DeleteRow(s.DatabaseID, "tickets", "t2"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Row("tickets", "t2"); ok {
		t.Fatal("delete not applied")
	}
	if _, err := tdb.GetRow(s.DatabaseID, "tickets", "missing"); err == nil {
		t.Fatal("missing row must 404")
	}
}

func TestTablesRefuseJWTAndGuests(t *testing.T) {
	s := apptest.New(t)
	s.Env(t)
	jwt := s.AddUser(apptest.User{ID: "u1"})
	clt, err := appwrite.NewClient(appwrite.ConfigFromEnv(openruntimes.Context{}))
	if err != nil {
		t.Fatal(err)
	}
	clt.AddHeader("X-Appwrite-JWT", jwt)
	tdb := tablesdb.New(clt)
	if _, err := tdb.ListRows(s.DatabaseID, "tickets"); err == nil {
		t.Fatal("a JWT caller must not read tables directly")
	}
	calls := s.Calls()
	if len(calls) != 1 || calls[0].Status != 401 || calls[0].Caller != "jwt:u1" || calls[0].Table != "tickets" {
		t.Fatalf("calls = %+v", calls)
	}
}

func TestTransactionRollbackUndoesWrites(t *testing.T) {
	s := apptest.New(t)
	s.Env(t)
	s.Seed("stock", "s1", map[string]any{"qty": 3})
	tdb := tables(t, s)
	tx, err := tdb.CreateTransaction()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tdb.UpdateRow(s.DatabaseID, "stock", "s1", tdb.WithUpdateRowData(map[string]any{"qty": 1}), tdb.WithUpdateRowTransactionId(tx.Id)); err != nil {
		t.Fatal(err)
	}
	if _, err := tdb.CreateOperations(tx.Id, tdb.WithCreateOperationsOperations([]any{
		map[string]any{"action": "create", "databaseId": s.DatabaseID, "tableId": "stock", "rowId": "s2", "data": map[string]any{"qty": 4}},
	})); err != nil {
		t.Fatal(err)
	}
	if _, err := tdb.UpdateTransaction(tx.Id, tdb.WithUpdateTransactionRollback(true)); err != nil {
		t.Fatal(err)
	}
	if row, _ := s.Row("stock", "s1"); row["qty"] != float64(3) {
		t.Fatalf("rollback left %+v", row)
	}
	if _, ok := s.Row("stock", "s2"); ok {
		t.Fatal("rollback left the created row")
	}
}

func TestUnhandledEndpointsAreReported(t *testing.T) {
	s := apptest.New(t)
	s.Env(t)
	clt, _ := appwrite.NewClient(appwrite.ConfigFromEnv(serverCtx(s)))
	_, err := clt.Call("GET", "/functions/f/executions", nil, nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	if got := s.Unhandled(); len(got) != 1 || got[0] != "GET /v1/functions/f/executions" {
		t.Fatalf("unhandled = %v", got)
	}
}

func TestSnapshotRestore(t *testing.T) {
	s := apptest.New(t)
	s.Seed("t", "a", map[string]any{"v": 1})
	snap := s.Snapshot()
	s.Seed("t", "b", map[string]any{"v": 2})
	s.Restore(snap)
	if len(s.Rows("t")) != 1 {
		t.Fatal("restore did not drop the new row")
	}
}

func TestStorageFilesServeTheirContent(t *testing.T) {
	s := apptest.New(t)
	s.Env(t)
	s.AddBucket("b1")
	s.AddFile("b1", "f1", "photo.png", []string{`read("team:t1")`}, []byte("hello"))
	clt, _ := appwrite.NewClient(appwrite.ConfigFromEnv(serverCtx(s)))
	got, err := clt.Call("GET", "/storage/buckets/b1/files/f1/view", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if body, ok := got.Result.([]byte); !ok || string(body) != "hello" {
		t.Fatalf("view = %#v", got.Result)
	}
	if rows := s.Rows(apptest.StorageTable("b1")); len(rows) != 1 {
		t.Fatalf("storage rows = %v", rows)
	}
	if _, err := clt.Call("GET", "/storage/buckets/b1/files/missing/view", nil, nil); err == nil {
		t.Fatal("a missing file must 404")
	}
}
