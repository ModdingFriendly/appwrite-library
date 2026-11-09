package appwrite

import (
	"strings"

	"github.com/appwrite/sdk-for-go/tablesdb"
	"github.com/open-runtimes/types-for-go/v4/openruntimes"

	"github.com/ModdingFriendly/appwrite-library/httpx"
)

// DefaultTransactionTTL is the transaction lifetime in seconds used by
// InTransaction. It is deliberately short: callers should create the
// transaction only after validation and commit immediately.
const DefaultTransactionTTL = 60

// InTransaction runs fn inside an Appwrite TablesDB transaction using
// configuration from the environment. The callback receives the TablesDB
// service and the transaction id; every row write it performs must pass the id
// through WithCreateRowTransactionId, WithUpdateRowTransactionId or
// WithDeleteRowTransactionId. The callback must not commit or roll back the
// transaction and must not perform non-transactional writes; those would fall
// outside the atomic unit.
//
// The transaction is committed only after fn returns nil and the commit
// acknowledgement is exactly "committed". Any callback error, commit error or
// ambiguous commit status returns an error and attempts a rollback; there is no
// non-transactional fallback.
func InTransaction(ctx openruntimes.Context, fn func(t *tablesdb.TablesDB, txID string) error) error {
	return InTransactionWith(ctx, ConfigFromEnv(ctx), fn)
}

// InTransactionWith is InTransaction with explicit configuration.
func InTransactionWith(ctx openruntimes.Context, cfg Config, fn func(t *tablesdb.TablesDB, txID string) error) error {
	if fn == nil {
		return httpx.BadRequest("transaction callback is required", nil)
	}

	clt, err := NewClient(cfg)
	if err != nil {
		return err
	}
	t := tablesdb.New(clt)
	tx, err := t.CreateTransaction(t.WithCreateTransactionTtl(DefaultTransactionTTL))
	if err != nil {
		ctx.Error("appwrite: create transaction: " + err.Error())
		return MapError(err, "transaction")
	}
	if tx == nil || strings.TrimSpace(tx.Id) == "" {
		ctx.Error("appwrite: create transaction returned no id")
		return httpx.Upstream("database transaction could not be created", nil)
	}

	committed := false
	defer func() {
		if committed {
			return
		}
		rollback(ctx, t, tx.Id)
	}()

	if err := fn(t, tx.Id); err != nil {
		return err
	}

	res, err := t.UpdateTransaction(tx.Id, t.WithUpdateTransactionCommit(true))
	if err != nil {
		ctx.Error("appwrite: commit transaction " + tx.Id + ": " + err.Error())
		return MapError(err, "transaction")
	}
	if res == nil {
		ctx.Error("appwrite: commit transaction " + tx.Id + " returned no acknowledgement")
		return httpx.Upstream("database transaction did not commit", map[string]any{"status": "missing"})
	}
	if res.Status != "committed" {
		status := res.Status
		if strings.TrimSpace(status) == "" {
			status = "empty"
		}
		// Fail closed. A pending/committing/failed or empty status is not proof
		// of a commit; the deferred rollback still runs.
		ctx.Error("appwrite: transaction " + tx.Id + " commit status " + status)
		return httpx.Upstream("database transaction did not commit", map[string]any{"status": status})
	}

	committed = true
	return nil
}

// rollback attempts to roll back an uncommitted transaction and logs a private
// error if the rollback fails or its acknowledgement is not "rolled_back".
func rollback(ctx openruntimes.Context, t *tablesdb.TablesDB, txID string) {
	res, err := t.UpdateTransaction(txID, t.WithUpdateTransactionRollback(true))
	if err != nil {
		ctx.Error("appwrite: rollback transaction " + txID + ": " + err.Error())
		return
	}
	if res == nil || res.Status != "rolled_back" {
		status := "missing"
		if res != nil {
			status = res.Status
			if strings.TrimSpace(status) == "" {
				status = "empty"
			}
		}
		ctx.Error("appwrite: transaction " + txID + " rollback status " + status)
	}
}
