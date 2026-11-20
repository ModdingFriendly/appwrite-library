// Package apptest is an in-memory Appwrite server for tests.
//
// It speaks the subset of the Appwrite REST API that Functions built on this
// library use: Account (JWT callers), Teams memberships, Users, and TablesDB
// rows with queries, bulk operations, increments and transactions. Point a
// Function at it with Server.Env and drive the real router: every request the
// handler makes goes over HTTP to the fake, exactly as it would in Production.
//
// # Access model
//
// The fake models Reparix's Production setup, where every table has an empty
// permission list:
//
//   - a request carrying the server key (X-Appwrite-Key equal to Server.APIKey)
//     may do anything;
//   - a JWT caller (X-Appwrite-JWT from Server.JWT) may read its own account
//     and the memberships of teams it belongs to, and nothing in TablesDB;
//   - anyone else is a guest and gets 401.
//
// # Recording
//
// Every request is recorded as a Call (method, path, caller, table, row and
// queries), so tests can assert what a handler asked for as well as what it
// answered. Requests for endpoints the fake does not implement answer 501 and
// are listed by Unhandled, so a gap in the fake is never mistaken for a
// refusal.
//
// Transactions are applied immediately and undone on rollback. That is enough
// for handler tests; it does not model isolation between concurrent
// transactions.
package apptest

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Row is one stored row: its column values plus the Appwrite system fields
// ($id, $sequence, $tableId, $databaseId, $createdAt, $updatedAt,
// $permissions).
type Row = map[string]any

// User is an Appwrite account known to the fake.
type User struct {
	ID       string
	Name     string
	Email    string
	Disabled bool
	Labels   []string
}

// Membership is a team membership known to the fake.
type Membership struct {
	ID        string
	TeamID    string
	UserID    string
	Roles     []string
	Confirmed bool
}

// Call is one recorded request.
type Call struct {
	Method string
	Path   string
	// Caller is "key", "jwt:<userID>" or "guest".
	Caller        string
	Table         string
	RowID         string
	Queries       []string
	TransactionID string
	Status        int
}

// Server is the fake. Create it with New; the zero value is not usable.
type Server struct {
	// ProjectID, DatabaseID and APIKey are what Env exports and what requests
	// must present. New fills them with fixed test values.
	ProjectID  string
	DatabaseID string
	APIKey     string

	srv *httptest.Server

	mu           sync.Mutex
	users        map[string]*User
	jwts         map[string]string
	memberships  []*Membership
	tables       map[string]map[string]Row
	unique       map[string][][]string
	seq          int
	clock        time.Time
	txs          map[string]*transaction
	buckets      map[string]map[string]any
	fileData     map[string][]byte
	teamsCreated map[string]bool
	calls        []Call
	unhandled    []string
}

type transaction struct {
	id     string
	status string
	ops    int
	undo   []func()
}

// New starts a fake server on plain HTTP (loopback) and stops it when the
// test ends.
func New(t testing.TB) *Server {
	t.Helper()
	return newServer(t, false)
}

// NewTLS starts the fake on HTTPS, for code that refuses a non-https
// endpoint. The test certificate is trusted by pointing SSL_CERT_FILE at it,
// which Go reads the first time the process verifies a certificate; call
// NewTLS before anything in the test binary makes a TLS connection.
func NewTLS(t testing.TB) *Server {
	t.Helper()
	return newServer(t, true)
}

func newServer(t testing.TB, useTLS bool) *Server {
	t.Helper()
	s := &Server{
		ProjectID:  "test-project",
		DatabaseID: "test-db",
		APIKey:     "test-server-key",
		users:      map[string]*User{},
		jwts:       map[string]string{},
		tables:     map[string]map[string]Row{},
		unique:     map[string][][]string{},
		clock:      time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC),
		txs:        map[string]*transaction{},
		buckets:    map[string]map[string]any{},
		fileData:   map[string][]byte{},
	}
	if !useTLS {
		s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
		t.Cleanup(s.srv.Close)
		return s
	}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	cert := s.srv.Certificate()
	path := filepath.Join(t.TempDir(), "apptest-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		t.Fatalf("apptest: %v", err)
	}
	t.Setenv("SSL_CERT_FILE", path)
	return s
}

// URL is the endpoint, including the /v1 prefix.
func (s *Server) URL() string { return s.srv.URL + "/v1" }

// Env points the Appwrite environment variables read by this library at the
// fake for the rest of the test.
func (s *Server) Env(t testing.TB) {
	t.Helper()
	t.Setenv("APPWRITE_ENDPOINT", s.URL())
	t.Setenv("APPWRITE_FUNCTION_API_ENDPOINT", s.URL())
	t.Setenv("APPWRITE_PROJECT_ID", s.ProjectID)
	t.Setenv("APPWRITE_FUNCTION_PROJECT_ID", s.ProjectID)
	t.Setenv("APPWRITE_DATABASE_ID", s.DatabaseID)
}

// AddUser registers an account and returns the JWT that authenticates it.
func (s *Server) AddUser(u User) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	copyUser := u
	s.users[u.ID] = &copyUser
	token := "jwt-" + u.ID
	s.jwts[token] = u.ID
	return token
}

// JWT returns the token for a registered user, or "" when there is none.
func (s *Server) JWT(userID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, id := range s.jwts {
		if id == userID {
			return token
		}
	}
	return ""
}

// AddMembership registers a team membership. An empty ID is generated.
func (s *Server) AddMembership(m Membership) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m.ID == "" {
		m.ID = fmt.Sprintf("mem-%s-%s", m.TeamID, m.UserID)
	}
	copyM := m
	copyM.Roles = append([]string(nil), m.Roles...)
	s.memberships = append(s.memberships, &copyM)
}

// UniqueIndex makes the fake answer 409 row_already_exists when a write would
// give two rows of table the same values for columns (nulls never collide).
func (s *Server) UniqueIndex(table string, columns ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unique[table] = append(s.unique[table], append([]string(nil), columns...))
}

// Seed stores a row as-is (no unique-index check). System fields are filled
// in; data may set $permissions.
func (s *Server) Seed(table, id string, data map[string]any) Row {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.newRow(table, id, data, nil)
	s.tableRows(table)[id] = row
	return cloneRow(row)
}

// Row returns a copy of a stored row.
func (s *Server) Row(table, id string) (Row, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.tables[table][id]
	if !ok {
		return nil, false
	}
	return cloneRow(row), true
}

// Rows returns copies of every row of a table, in $sequence order.
func (s *Server) Rows(table string) []Row {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sortedRows(table)
}

// Tables lists the table ids that hold at least one row.
func (s *Server) Tables() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for name, rows := range s.tables {
		if len(rows) > 0 {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// AddFile stores a file in bucket. Files appear in snapshots as rows of the
// pseudo-table "storage:<bucket>", carrying $permissions and name.
func (s *Server) AddFile(bucket, id, name string, permissions []string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.newRow(StorageTable(bucket), id, map[string]any{"name": name, "mimeType": "application/octet-stream", "sizeOriginal": len(data)}, permissions)
	s.tableRows(StorageTable(bucket))[id] = row
	s.fileData[bucket+"/"+id] = append([]byte(nil), data...)
}

// fileContent is a raw file body (view, download, preview).
type fileContent struct {
	data []byte
	mime string
}

// StorageTable is the pseudo-table name that holds bucket's files.
func StorageTable(bucket string) string { return "storage:" + bucket }

// Snapshot is a deep copy of every table, keyed table -> row id.
type Snapshot map[string]map[string]Row

// Snapshot copies the whole store.
func (s *Server) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := Snapshot{}
	for name, rows := range s.tables {
		copyRows := map[string]Row{}
		for id, row := range rows {
			copyRows[id] = cloneRow(row)
		}
		out[name] = copyRows
	}
	members := map[string]Row{}
	for _, m := range s.memberships {
		members[m.ID] = Row{"$id": m.ID, "organization_id": m.TeamID, "userId": m.UserID, "roles": toAny(m.Roles), "confirm": m.Confirmed}
	}
	out[MembershipsTable] = members
	return out
}

// MembershipsTable is the pseudo-table under which snapshots carry team
// memberships, each with organization_id set to its team.
const MembershipsTable = "teams:memberships"

func toAny(values []string) []any {
	out := make([]any, 0, len(values))
	for _, v := range values {
		out = append(out, v)
	}
	return out
}

// Restore replaces the store with a snapshot, so one fixture can serve many
// requests without one request's writes leaking into the next.
func (s *Server) Restore(snap Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tables = map[string]map[string]Row{}
	if members, ok := snap[MembershipsTable]; ok {
		s.memberships = nil
		ids := make([]string, 0, len(members))
		for id := range members {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			row := members[id]
			team, _ := row["organization_id"].(string)
			user, _ := row["userId"].(string)
			confirmed, _ := row["confirm"].(bool)
			s.memberships = append(s.memberships, &Membership{ID: id, TeamID: team, UserID: user, Roles: stringList(row["roles"]), Confirmed: confirmed})
		}
	}
	for name, rows := range snap {
		if name == MembershipsTable {
			continue
		}
		copyRows := map[string]Row{}
		for id, row := range rows {
			copyRows[id] = cloneRow(row)
		}
		s.tables[name] = copyRows
	}
}

// Calls returns the recorded requests.
func (s *Server) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Call(nil), s.calls...)
}

// ResetCalls forgets recorded requests and unhandled endpoints.
func (s *Server) ResetCalls() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = nil
	s.unhandled = nil
}

// Unhandled lists "METHOD path" for requests the fake does not implement.
func (s *Server) Unhandled() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.unhandled...)
}

// ---------------------------------------------------------------------------
// HTTP

type apiError struct {
	status int
	typ    string
	msg    string
}

func errorf(status int, typ, format string, args ...any) *apiError {
	return &apiError{status: status, typ: typ, msg: fmt.Sprintf(format, args...)}
}

type request struct {
	method  string
	parts   []string
	caller  string
	userID  string
	params  map[string]any
	queries []string
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, perr := s.parse(r)
	call := Call{Method: r.Method, Path: r.URL.Path}
	var status int
	var body any
	if perr != nil {
		status, body = perr.status, errorBody(perr)
	} else {
		call.Caller = req.caller
		call.Queries = req.queries
		call.TransactionID, _ = req.params["transactionId"].(string)
		if len(req.parts) >= 5 && req.parts[0] == "tablesdb" && req.parts[2] == "tables" {
			call.Table = req.parts[3]
			if len(req.parts) >= 6 {
				call.RowID = req.parts[5]
			}
		}
		out, err := s.route(req)
		switch {
		case err != nil:
			status, body = err.status, errorBody(err)
			if err.status == http.StatusNotImplemented {
				s.unhandled = append(s.unhandled, r.Method+" "+r.URL.Path)
			}
		case out == nil:
			status = http.StatusNoContent
		default:
			status, body = http.StatusOK, out
			if r.Method == http.MethodPost && call.Table != "" {
				status = http.StatusCreated
			}
		}
	}
	call.Status = status
	s.calls = append(s.calls, call)

	if body == nil {
		w.WriteHeader(status)
		return
	}
	if file, ok := body.(fileContent); ok {
		w.Header().Set("Content-Type", file.mime)
		w.WriteHeader(status)
		_, _ = w.Write(file.data)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func errorBody(e *apiError) map[string]any {
	return map[string]any{"message": e.msg, "code": e.status, "type": e.typ, "version": "1.8.0"}
}

func (s *Server) parse(r *http.Request) (*request, *apiError) {
	path := strings.TrimPrefix(r.URL.Path, "/v1")
	path = strings.Trim(path, "/")
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if u, err := url.PathUnescape(p); err == nil {
			parts[i] = u
		}
	}
	req := &request{method: r.Method, parts: parts, params: map[string]any{}}

	if r.Header.Get("X-Appwrite-Project") != s.ProjectID {
		return nil, errorf(404, "project_not_found", "project not found")
	}
	switch {
	case r.Header.Get("X-Appwrite-Key") != "":
		if r.Header.Get("X-Appwrite-Key") != s.APIKey {
			return nil, errorf(401, "general_unauthorized_scope", "invalid API key")
		}
		req.caller = "key"
	case r.Header.Get("X-Appwrite-JWT") != "":
		id, ok := s.jwts[r.Header.Get("X-Appwrite-JWT")]
		if !ok {
			return nil, errorf(401, "user_jwt_invalid", "invalid JWT")
		}
		req.caller, req.userID = "jwt:"+id, id
	default:
		req.caller = "guest"
	}

	if r.Method == http.MethodGet {
		q := r.URL.Query()
		for key, values := range q {
			if strings.HasSuffix(key, "[]") {
				list := make([]any, 0, len(values))
				for _, v := range values {
					list = append(list, v)
				}
				req.params[strings.TrimSuffix(key, "[]")] = list
				continue
			}
			req.params[key] = values[0]
		}
	} else if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			return nil, errorf(400, "general_argument_invalid", "invalid multipart body")
		}
		perms := map[int]string{}
		for key, values := range r.MultipartForm.Value {
			var i int
			if n, _ := fmt.Sscanf(key, "permissions[%d]", &i); n == 1 {
				perms[i] = values[0]
				continue
			}
			req.params[key] = values[0]
		}
		list := make([]any, len(perms))
		for i, v := range perms {
			if i < len(list) {
				list[i] = v
			}
		}
		req.params["permissions"] = list
		if headers := r.MultipartForm.File["file"]; len(headers) > 0 {
			f, err := headers[0].Open()
			if err == nil {
				data, _ := io.ReadAll(f)
				_ = f.Close()
				req.params["__file"] = data
				req.params["__fileName"] = headers[0].Filename
				req.params["__mimeType"] = headers[0].Header.Get("Content-Type")
			}
		}
	} else if r.Body != nil {
		raw, _ := io.ReadAll(r.Body)
		if len(strings.TrimSpace(string(raw))) > 0 {
			if err := json.Unmarshal(raw, &req.params); err != nil {
				return nil, errorf(400, "general_argument_invalid", "invalid JSON body")
			}
		}
	}
	req.queries = stringList(req.params["queries"])
	return req, nil
}

func (s *Server) route(req *request) (any, *apiError) {
	p := req.parts
	switch {
	case len(p) == 1 && p[0] == "account" && req.method == http.MethodGet:
		return s.account(req)
	case len(p) == 1 && p[0] == "teams" && req.method == http.MethodPost:
		if req.caller != "key" {
			return nil, errorf(401, "general_unauthorized_scope", "server key required")
		}
		id, _ := req.params["teamId"].(string)
		if id == "" || id == "unique()" {
			id = s.newID()
		}
		if s.teamsCreated == nil {
			s.teamsCreated = map[string]bool{}
		}
		if s.teamsCreated[id] {
			return nil, errorf(409, "team_already_exists", "team already exists")
		}
		s.teamsCreated[id] = true
		name, _ := req.params["name"].(string)
		return map[string]any{"$id": id, "name": name, "total": 0, "prefs": map[string]any{}, "$createdAt": s.stamp(), "$updatedAt": s.stamp()}, nil
	case len(p) >= 2 && p[0] == "teams":
		return s.teams(req)
	case len(p) >= 1 && p[0] == "users":
		return s.usersRoute(req)
	case len(p) <= 3 && len(p) >= 2 && p[0] == "storage" && p[1] == "buckets":
		if req.caller != "key" {
			return nil, errorf(401, "user_unauthorized", "server key required")
		}
		return s.bucketsRoute(req)
	case len(p) >= 4 && p[0] == "storage" && p[1] == "buckets" && p[3] == "files":
		if req.caller != "key" {
			return nil, errorf(401, "user_unauthorized", "server key required")
		}
		return s.files(req)
	case len(p) == 3 && p[0] == "messaging" && p[1] == "messages" && req.method == http.MethodPost:
		// Sending a message: recorded under the pseudo-table
		// "messaging:<kind>" so tests can see what would have gone out.
		if req.caller != "key" {
			return nil, errorf(401, "general_unauthorized_scope", "server key required")
		}
		id, _ := req.params["messageId"].(string)
		if id == "" || id == "unique()" {
			id = s.newID()
		}
		data := map[string]any{}
		for k, v := range req.params {
			if k != "messageId" {
				data[k] = v
			}
		}
		row := s.newRow("messaging:"+p[2], id, data, nil)
		s.tableRows("messaging:" + p[2])[id] = row
		out := map[string]any{"$id": id, "$createdAt": row["$createdAt"], "$updatedAt": row["$updatedAt"], "providerType": p[2], "status": "processing", "deliveredTotal": 0}
		return out, nil
	case len(p) >= 2 && p[0] == "tablesdb" && p[1] == "transactions":
		if req.caller != "key" {
			return nil, errorf(401, "general_unauthorized_scope", "server key required")
		}
		return s.transactions(req)
	case len(p) >= 5 && p[0] == "tablesdb" && p[2] == "tables" && p[4] == "rows":
		if req.caller != "key" {
			// Every Production table has an empty permission list.
			return nil, errorf(401, "user_unauthorized", "the current user is not authorized to perform the requested action")
		}
		if p[1] != s.DatabaseID {
			return nil, errorf(404, "database_not_found", "database %s not found", p[1])
		}
		return s.rows(req)
	}
	return nil, errorf(http.StatusNotImplemented, "apptest_unhandled", "apptest does not implement %s /%s", req.method, strings.Join(p, "/"))
}

// ---------------------------------------------------------------------------
// Account, teams, users

func (s *Server) userJSON(u *User) map[string]any {
	return map[string]any{
		"$id": u.ID, "$createdAt": s.stamp(), "$updatedAt": s.stamp(),
		"name": u.Name, "email": u.Email, "status": !u.Disabled,
		"labels": nonNil(u.Labels), "prefs": map[string]any{}, "targets": []any{},
		"registration": s.stamp(), "emailVerification": true,
	}
}

func (s *Server) account(req *request) (any, *apiError) {
	if req.userID == "" {
		return nil, errorf(401, "general_unauthorized_scope", "account requires a user session")
	}
	return s.userJSON(s.users[req.userID]), nil
}

func (s *Server) membershipJSON(m *Membership) map[string]any {
	u := s.users[m.UserID]
	name, email := "", ""
	if u != nil {
		name, email = u.Name, u.Email
	}
	return map[string]any{
		"$id": m.ID, "$createdAt": s.stamp(), "$updatedAt": s.stamp(),
		"userId": m.UserID, "userName": name, "userEmail": email,
		"teamId": m.TeamID, "teamName": m.TeamID, "invited": s.stamp(), "joined": s.stamp(),
		"confirm": m.Confirmed, "mfa": false, "roles": nonNil(m.Roles),
	}
}

func (s *Server) isMember(teamID, userID string) bool {
	for _, m := range s.memberships {
		if m.TeamID == teamID && m.UserID == userID {
			return true
		}
	}
	return false
}

// canManageTeam: the server key, or a JWT caller holding the owner role.
func (s *Server) canManageTeam(req *request, teamID string) bool {
	if req.caller == "key" {
		return true
	}
	for _, m := range s.memberships {
		if m.TeamID == teamID && m.UserID == req.userID && m.Confirmed {
			for _, r := range m.Roles {
				if r == "owner" {
					return true
				}
			}
		}
	}
	return false
}

func (s *Server) teams(req *request) (any, *apiError) {
	p := req.parts
	teamID := p[1]
	if req.caller == "guest" {
		return nil, errorf(401, "general_unauthorized_scope", "guests cannot read teams")
	}
	if len(p) == 2 && p[1] == "" {
		return nil, errorf(404, "team_not_found", "team not found")
	}
	if req.caller != "key" && !s.isMember(teamID, req.userID) {
		return nil, errorf(404, "team_not_found", "team not found")
	}
	switch {
	case len(p) == 2 && req.method == http.MethodGet:
		return map[string]any{"$id": teamID, "name": teamID, "total": 0, "prefs": map[string]any{}}, nil
	case len(p) == 3 && p[2] == "memberships" && req.method == http.MethodGet:
		var rows []Row
		for _, m := range s.memberships {
			if m.TeamID != teamID {
				continue
			}
			rows = append(rows, Row(s.membershipJSON(m)))
		}
		page, total, err := applyQueries(rows, req.queries)
		if err != nil {
			return nil, err
		}
		return map[string]any{"total": total, "memberships": page}, nil
	case len(p) == 4 && p[2] == "memberships" && req.method == http.MethodGet:
		for _, m := range s.memberships {
			if m.TeamID == teamID && m.ID == p[3] {
				return s.membershipJSON(m), nil
			}
		}
		return nil, errorf(404, "membership_not_found", "membership not found")
	case len(p) == 3 && p[2] == "memberships" && req.method == http.MethodPost:
		if !s.canManageTeam(req, teamID) {
			return nil, errorf(401, "user_unauthorized", "only a team owner or the server key can invite")
		}
		userID, _ := req.params["userId"].(string)
		email, _ := req.params["email"].(string)
		if userID == "" {
			for id, u := range s.users {
				if email != "" && strings.EqualFold(u.Email, email) {
					userID = id
				}
			}
		}
		if userID == "" {
			userID = s.newID()
			name, _ := req.params["name"].(string)
			s.users[userID] = &User{ID: userID, Name: name, Email: email}
			s.jwts["jwt-"+userID] = userID
		}
		for _, m := range s.memberships {
			if m.TeamID == teamID && m.UserID == userID {
				return nil, errorf(409, "team_invite_already_exists", "user is already a member")
			}
		}
		m := &Membership{ID: s.newID(), TeamID: teamID, UserID: userID, Roles: stringList(req.params["roles"]), Confirmed: req.caller == "key"}
		s.memberships = append(s.memberships, m)
		return s.membershipJSON(m), nil
	case len(p) == 4 && p[2] == "memberships" && (req.method == http.MethodPatch || req.method == http.MethodDelete):
		if !s.canManageTeam(req, teamID) {
			return nil, errorf(401, "user_unauthorized", "only a team owner or the server key can change memberships")
		}
		for i, m := range s.memberships {
			if m.TeamID != teamID || m.ID != p[3] {
				continue
			}
			if req.method == http.MethodDelete {
				s.memberships = append(s.memberships[:i], s.memberships[i+1:]...)
				return nil, nil
			}
			m.Roles = stringList(req.params["roles"])
			return s.membershipJSON(m), nil
		}
		return nil, errorf(404, "membership_not_found", "membership not found")
	}
	return nil, errorf(http.StatusNotImplemented, "apptest_unhandled", "apptest does not implement %s /%s", req.method, strings.Join(p, "/"))
}

func (s *Server) usersRoute(req *request) (any, *apiError) {
	if req.caller != "key" {
		return nil, errorf(401, "general_unauthorized_scope", "server key required")
	}
	p := req.parts
	switch {
	case len(p) == 2 && req.method == http.MethodGet:
		u, ok := s.users[p[1]]
		if !ok {
			return nil, errorf(404, "user_not_found", "user not found")
		}
		return s.userJSON(u), nil
	case len(p) == 1 && req.method == http.MethodGet:
		var rows []Row
		ids := make([]string, 0, len(s.users))
		for id := range s.users {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			rows = append(rows, Row(s.userJSON(s.users[id])))
		}
		page, total, err := applyQueries(rows, req.queries)
		if err != nil {
			return nil, err
		}
		return map[string]any{"total": total, "users": page}, nil
	case len(p) == 3 && p[2] == "targets" && req.method == http.MethodGet:
		u, ok := s.users[p[1]]
		if !ok {
			return nil, errorf(404, "user_not_found", "user not found")
		}
		targets := []any{}
		if u.Email != "" {
			targets = append(targets, map[string]any{"$id": "target-" + u.ID, "userId": u.ID, "providerType": "email", "identifier": u.Email, "name": u.Name, "expired": false})
		}
		return map[string]any{"total": len(targets), "targets": targets}, nil
	case len(p) == 3 && p[2] == "memberships" && req.method == http.MethodGet:
		var rows []Row
		for _, m := range s.memberships {
			if m.UserID == p[1] {
				rows = append(rows, Row(s.membershipJSON(m)))
			}
		}
		return map[string]any{"total": len(rows), "memberships": nonNilRows(rows)}, nil
	}
	return nil, errorf(http.StatusNotImplemented, "apptest_unhandled", "apptest does not implement %s /%s", req.method, strings.Join(p, "/"))
}

// ---------------------------------------------------------------------------
// TablesDB rows

func (s *Server) tableRows(table string) map[string]Row {
	rows, ok := s.tables[table]
	if !ok {
		rows = map[string]Row{}
		s.tables[table] = rows
	}
	return rows
}

func (s *Server) sortedRows(table string) []Row {
	rows := s.tables[table]
	out := make([]Row, 0, len(rows))
	for _, row := range rows {
		out = append(out, cloneRow(row))
	}
	sort.SliceStable(out, func(i, j int) bool { return seqOf(out[i]) < seqOf(out[j]) })
	return out
}

func (s *Server) stamp() string {
	return s.clock.Format("2006-01-02T15:04:05.000+00:00")
}

func (s *Server) tick() string {
	s.clock = s.clock.Add(time.Millisecond)
	return s.stamp()
}

func (s *Server) newID() string {
	s.seq++
	return fmt.Sprintf("row%06d", s.seq)
}

func (s *Server) newRow(table, id string, data map[string]any, permissions []string) Row {
	s.seq++
	now := s.tick()
	row := Row{}
	for k, v := range data {
		row[k] = v
	}
	if perms, ok := data["$permissions"]; ok && permissions == nil {
		permissions = stringList(perms)
	}
	row["$id"] = id
	row["$sequence"] = s.seq
	row["$tableId"] = table
	row["$databaseId"] = s.DatabaseID
	row["$createdAt"] = now
	row["$updatedAt"] = now
	row["$permissions"] = nonNil(permissions)
	return row
}

func (s *Server) txFor(req *request) (*transaction, *apiError) {
	id, _ := req.params["transactionId"].(string)
	if id == "" {
		return nil, nil
	}
	tx, ok := s.txs[id]
	if !ok {
		return nil, errorf(404, "transaction_not_found", "transaction %s not found", id)
	}
	if tx.status != "pending" {
		return nil, errorf(409, "transaction_conflict", "transaction %s is %s", id, tx.status)
	}
	return tx, nil
}

func (s *Server) rows(req *request) (any, *apiError) {
	p := req.parts
	table := p[3]
	tx, err := s.txFor(req)
	if err != nil {
		return nil, err
	}
	if tx != nil && req.method != http.MethodGet {
		tx.ops++
	}
	switch {
	case len(p) == 5 && req.method == http.MethodGet:
		page, total, err := applyQueries(s.sortedRows(table), req.queries)
		if err != nil {
			return nil, err
		}
		if t, ok := req.params["total"]; ok && (t == false || t == "false") {
			total = 0
		}
		return map[string]any{"total": total, "rows": page}, nil
	case len(p) == 5 && req.method == http.MethodPost:
		if list, ok := req.params["rows"].([]any); ok {
			var out []Row
			for _, item := range list {
				data, _ := item.(map[string]any)
				id, _ := data["$id"].(string)
				row, err := s.create(tx, table, id, data, nil)
				if err != nil {
					return nil, err
				}
				out = append(out, row)
			}
			return map[string]any{"total": len(out), "rows": nonNilRows(out)}, nil
		}
		id, _ := req.params["rowId"].(string)
		data, _ := req.params["data"].(map[string]any)
		var perms []string
		if raw, ok := req.params["permissions"]; ok {
			perms = stringList(raw)
		}
		return s.create(tx, table, id, data, perms)
	case len(p) == 5 && req.method == http.MethodPut:
		list, _ := req.params["rows"].([]any)
		var out []Row
		for _, item := range list {
			data, _ := item.(map[string]any)
			id, _ := data["$id"].(string)
			row, err := s.upsert(tx, table, id, data, nil)
			if err != nil {
				return nil, err
			}
			out = append(out, row)
		}
		return map[string]any{"total": len(out), "rows": nonNilRows(out)}, nil
	case len(p) == 5 && req.method == http.MethodPatch:
		data, _ := req.params["data"].(map[string]any)
		matched, _, err := applyQueries(s.sortedRows(table), withoutPaging(req.queries))
		if err != nil {
			return nil, err
		}
		var out []Row
		for _, row := range matched {
			updated, err := s.update(tx, table, row["$id"].(string), data)
			if err != nil {
				return nil, err
			}
			out = append(out, updated)
		}
		return map[string]any{"total": len(out), "rows": nonNilRows(out)}, nil
	case len(p) == 5 && req.method == http.MethodDelete:
		matched, _, err := applyQueries(s.sortedRows(table), withoutPaging(req.queries))
		if err != nil {
			return nil, err
		}
		for _, row := range matched {
			s.remove(tx, table, row["$id"].(string))
		}
		return map[string]any{"total": len(matched), "rows": nonNilRows(matched)}, nil
	case len(p) == 6 && req.method == http.MethodGet:
		row, ok := s.tables[table][p[5]]
		if !ok {
			return nil, errorf(404, "row_not_found", "row with the requested ID could not be found")
		}
		page, _, err := applyQueries([]Row{cloneRow(row)}, req.queries)
		if err != nil {
			return nil, err
		}
		return page[0], nil
	case len(p) == 6 && req.method == http.MethodPatch:
		data, _ := req.params["data"].(map[string]any)
		if raw, ok := req.params["permissions"]; ok {
			if data == nil {
				data = map[string]any{}
			}
			data["$permissions"] = stringList(raw)
		}
		return s.update(tx, table, p[5], data)
	case len(p) == 6 && req.method == http.MethodPut:
		data, _ := req.params["data"].(map[string]any)
		var perms []string
		if raw, ok := req.params["permissions"]; ok {
			perms = stringList(raw)
		}
		return s.upsert(tx, table, p[5], data, perms)
	case len(p) == 6 && req.method == http.MethodDelete:
		if _, ok := s.tables[table][p[5]]; !ok {
			return nil, errorf(404, "row_not_found", "row with the requested ID could not be found")
		}
		s.remove(tx, table, p[5])
		return nil, nil
	case len(p) == 8 && req.method == http.MethodPatch && (p[7] == "increment" || p[7] == "decrement"):
		return s.increment(tx, table, p[5], p[6], p[7] == "decrement", req.params)
	}
	return nil, errorf(http.StatusNotImplemented, "apptest_unhandled", "apptest does not implement %s /%s", req.method, strings.Join(p, "/"))
}

func (s *Server) checkUnique(table string, row Row) *apiError {
	for _, cols := range s.unique[table] {
		for id, other := range s.tables[table] {
			if id == row["$id"] {
				continue
			}
			same := true
			for _, c := range cols {
				a, b := row[c], other[c]
				if a == nil || b == nil || fmt.Sprint(a) != fmt.Sprint(b) {
					same = false
					break
				}
			}
			if same {
				return errorf(409, "row_already_exists", "a row with the same unique values already exists")
			}
		}
	}
	return nil
}

func (s *Server) record(tx *transaction, undo func()) {
	if tx != nil {
		tx.undo = append(tx.undo, undo)
	}
}

func (s *Server) create(tx *transaction, table, id string, data map[string]any, perms []string) (Row, *apiError) {
	if id == "" || id == "unique()" {
		id = s.newID()
	}
	rows := s.tableRows(table)
	if _, exists := rows[id]; exists {
		return nil, errorf(409, "row_already_exists", "row with the requested ID already exists")
	}
	row := s.newRow(table, id, stripSystem(data), perms)
	if err := s.checkUnique(table, row); err != nil {
		return nil, err
	}
	rows[id] = row
	s.record(tx, func() { delete(s.tableRows(table), id) })
	return cloneRow(row), nil
}

func (s *Server) update(tx *transaction, table, id string, data map[string]any) (Row, *apiError) {
	rows := s.tableRows(table)
	old, ok := rows[id]
	if !ok {
		return nil, errorf(404, "row_not_found", "row with the requested ID could not be found")
	}
	row := cloneRow(old)
	for k, v := range data {
		if k == "$permissions" {
			row[k] = nonNil(stringList(v))
			continue
		}
		if strings.HasPrefix(k, "$") {
			continue
		}
		row[k] = v
	}
	row["$updatedAt"] = s.tick()
	if err := s.checkUnique(table, row); err != nil {
		return nil, err
	}
	rows[id] = row
	s.record(tx, func() { s.tableRows(table)[id] = old })
	return cloneRow(row), nil
}

func (s *Server) upsert(tx *transaction, table, id string, data map[string]any, perms []string) (Row, *apiError) {
	if _, ok := s.tableRows(table)[id]; ok {
		if perms != nil {
			data = cloneRow(data)
			data["$permissions"] = perms
		}
		return s.update(tx, table, id, data)
	}
	return s.create(tx, table, id, data, perms)
}

func (s *Server) remove(tx *transaction, table, id string) {
	rows := s.tableRows(table)
	old, ok := rows[id]
	if !ok {
		return
	}
	delete(rows, id)
	s.record(tx, func() { s.tableRows(table)[id] = old })
}

func (s *Server) increment(tx *transaction, table, id, column string, decrement bool, params map[string]any) (Row, *apiError) {
	row, ok := s.tableRows(table)[id]
	if !ok {
		return nil, errorf(404, "row_not_found", "row with the requested ID could not be found")
	}
	by := 1.0
	if v, ok := toFloat(params["value"]); ok {
		by = v
	}
	cur, _ := toFloat(row[column])
	next := cur + by
	if decrement {
		next = cur - by
		if min, ok := toFloat(params["min"]); ok && next < min {
			return nil, errorf(400, "row_invalid_structure", "value would go below the minimum")
		}
	} else if max, ok := toFloat(params["max"]); ok && next > max {
		return nil, errorf(400, "row_invalid_structure", "value would go above the maximum")
	}
	var value any = next
	if next == float64(int64(next)) {
		value = int64(next)
	}
	return s.update(tx, table, id, map[string]any{column: value})
}

// ---------------------------------------------------------------------------
// Storage

// AddBucket registers a storage bucket.
func (s *Server) AddBucket(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buckets[id] = map[string]any{"$id": id, "name": id, "enabled": true, "fileSecurity": true, "$permissions": []string{}}
}

func (s *Server) bucketsRoute(req *request) (any, *apiError) {
	p := req.parts
	switch {
	case len(p) == 2 && req.method == http.MethodPost:
		id, _ := req.params["bucketId"].(string)
		if id == "" || id == "unique()" {
			id = s.newID()
		}
		if _, exists := s.buckets[id]; exists {
			return nil, errorf(409, "storage_bucket_already_exists", "bucket already exists")
		}
		b := map[string]any{"$id": id, "$createdAt": s.stamp(), "$updatedAt": s.stamp(), "enabled": true}
		for k, v := range req.params {
			if k != "bucketId" {
				b[k] = v
			}
		}
		s.buckets[id] = b
		return b, nil
	case len(p) == 3 && req.method == http.MethodGet:
		b, ok := s.buckets[p[2]]
		if !ok {
			return nil, errorf(404, "storage_bucket_not_found", "bucket not found")
		}
		return b, nil
	case len(p) == 3 && req.method == http.MethodPut:
		b, ok := s.buckets[p[2]]
		if !ok {
			return nil, errorf(404, "storage_bucket_not_found", "bucket not found")
		}
		for k, v := range req.params {
			if k != "bucketId" {
				b[k] = v
			}
		}
		return b, nil
	}
	return nil, errorf(http.StatusNotImplemented, "apptest_unhandled", "apptest does not implement %s /%s", req.method, strings.Join(p, "/"))
}

func (s *Server) fileJSON(bucket string, row Row) map[string]any {
	out := map[string]any{"bucketId": bucket, "chunksTotal": 1, "chunksUploaded": 1, "signature": "sig"}
	for k, v := range row {
		out[k] = v
	}
	return out
}

func (s *Server) files(req *request) (any, *apiError) {
	p := req.parts
	bucket := p[2]
	table := StorageTable(bucket)
	switch {
	case len(p) == 4 && req.method == http.MethodPost:
		id, _ := req.params["fileId"].(string)
		if id == "" || id == "unique()" {
			id = s.newID()
		}
		if _, exists := s.tableRows(table)[id]; exists {
			return nil, errorf(409, "storage_file_already_exists", "file already exists")
		}
		data, _ := req.params["__file"].([]byte)
		name, _ := req.params["__fileName"].(string)
		mime, _ := req.params["__mimeType"].(string)
		row := s.newRow(table, id, map[string]any{"name": name, "mimeType": mime, "sizeOriginal": len(data)}, stringList(req.params["permissions"]))
		s.tableRows(table)[id] = row
		s.fileData[bucket+"/"+id] = append([]byte(nil), data...)
		return s.fileJSON(bucket, row), nil
	case len(p) == 4 && req.method == http.MethodGet:
		page, total, err := applyQueries(s.sortedRows(table), req.queries)
		if err != nil {
			return nil, err
		}
		files := make([]any, 0, len(page))
		for _, row := range page {
			files = append(files, s.fileJSON(bucket, row))
		}
		return map[string]any{"total": total, "files": files}, nil
	case len(p) >= 5:
		row, ok := s.tableRows(table)[p[4]]
		if !ok {
			return nil, errorf(404, "storage_file_not_found", "file not found")
		}
		switch {
		case len(p) == 5 && req.method == http.MethodGet:
			return s.fileJSON(bucket, cloneRow(row)), nil
		case len(p) == 5 && req.method == http.MethodDelete:
			delete(s.tableRows(table), p[4])
			return nil, nil
		case len(p) == 6 && req.method == http.MethodGet && (p[5] == "view" || p[5] == "download" || p[5] == "preview"):
			mime, _ := row["mimeType"].(string)
			return fileContent{data: s.fileData[bucket+"/"+p[4]], mime: mime}, nil
		}
	}
	return nil, errorf(http.StatusNotImplemented, "apptest_unhandled", "apptest does not implement %s /%s", req.method, strings.Join(p, "/"))
}

// ---------------------------------------------------------------------------
// Transactions

func (s *Server) txJSON(tx *transaction) map[string]any {
	return map[string]any{
		"$id": tx.id, "$createdAt": s.stamp(), "$updatedAt": s.stamp(),
		"status": tx.status, "operations": tx.ops, "expiresAt": s.clock.Add(time.Minute).Format(time.RFC3339),
	}
}

func (s *Server) transactions(req *request) (any, *apiError) {
	p := req.parts
	switch {
	case len(p) == 2 && req.method == http.MethodPost:
		s.seq++
		tx := &transaction{id: fmt.Sprintf("tx%06d", s.seq), status: "pending"}
		s.txs[tx.id] = tx
		return s.txJSON(tx), nil
	case len(p) >= 3:
		tx, ok := s.txs[p[2]]
		if !ok {
			return nil, errorf(404, "transaction_not_found", "transaction not found")
		}
		switch {
		case len(p) == 3 && req.method == http.MethodGet:
			return s.txJSON(tx), nil
		case len(p) == 3 && req.method == http.MethodPatch:
			if tx.status != "pending" {
				return nil, errorf(409, "transaction_conflict", "transaction is %s", tx.status)
			}
			if req.params["rollback"] == true {
				for i := len(tx.undo) - 1; i >= 0; i-- {
					tx.undo[i]()
				}
				tx.undo = nil
				tx.status = "rolledBack"
			} else if req.params["commit"] == true {
				tx.status = "committed"
			}
			return s.txJSON(tx), nil
		case len(p) == 3 && req.method == http.MethodDelete:
			for i := len(tx.undo) - 1; i >= 0; i-- {
				tx.undo[i]()
			}
			delete(s.txs, tx.id)
			return nil, nil
		case len(p) == 4 && p[3] == "operations" && req.method == http.MethodPost:
			if tx.status != "pending" {
				return nil, errorf(409, "transaction_conflict", "transaction is %s", tx.status)
			}
			ops, _ := req.params["operations"].([]any)
			for _, raw := range ops {
				op, _ := raw.(map[string]any)
				if err := s.applyOperation(tx, op); err != nil {
					return nil, err
				}
				tx.ops++
			}
			return s.txJSON(tx), nil
		}
	}
	return nil, errorf(http.StatusNotImplemented, "apptest_unhandled", "apptest does not implement %s /%s", req.method, strings.Join(p, "/"))
}

func (s *Server) applyOperation(tx *transaction, op map[string]any) *apiError {
	action, _ := op["action"].(string)
	table, _ := op["tableId"].(string)
	id, _ := op["rowId"].(string)
	data, _ := op["data"].(map[string]any)
	if db, _ := op["databaseId"].(string); db != "" && db != s.DatabaseID {
		return errorf(404, "database_not_found", "database %s not found", db)
	}
	var err *apiError
	switch action {
	case "create":
		_, err = s.create(tx, table, id, data, nil)
	case "update":
		_, err = s.update(tx, table, id, data)
	case "upsert":
		_, err = s.upsert(tx, table, id, data, nil)
	case "delete":
		if _, ok := s.tableRows(table)[id]; !ok {
			return errorf(404, "row_not_found", "row with the requested ID could not be found")
		}
		s.remove(tx, table, id)
	case "increment", "decrement":
		column, _ := data["column"].(string)
		_, err = s.increment(tx, table, id, column, action == "decrement", data)
	default:
		return errorf(http.StatusNotImplemented, "apptest_unhandled", "apptest does not implement transaction action %q", action)
	}
	return err
}

// ---------------------------------------------------------------------------
// helpers

func cloneRow(row map[string]any) Row {
	if row == nil {
		return nil
	}
	raw, _ := json.Marshal(row)
	out := Row{}
	_ = json.Unmarshal(raw, &out)
	return out
}

func stripSystem(data map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range data {
		if strings.HasPrefix(k, "$") && k != "$permissions" {
			continue
		}
		out[k] = v
	}
	return out
}

func seqOf(row Row) float64 {
	v, _ := toFloat(row["$sequence"])
	return v
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func nonNilRows(rows []Row) []Row {
	if rows == nil {
		return []Row{}
	}
	return rows
}

func stringList(v any) []string {
	switch list := v.(type) {
	case []string:
		return list
	case []any:
		out := make([]string, 0, len(list))
		for _, item := range list {
			out = append(out, fmt.Sprint(item))
		}
		return out
	case string:
		if list == "" {
			return nil
		}
		return []string{list}
	}
	return nil
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(n, 64)
		return f, err == nil
	}
	return 0, false
}
