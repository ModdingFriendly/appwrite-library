// Package rows holds the strict, consumer-parameterised row gateway engines:
// a read engine and a mutation engine, plus the field parsing, query
// validation, read-ACL builders, numeric and size limits and error mapping
// they share.
//
// The package ships NO table policy and no product role names. Each consuming
// Function supplies the subset of tables it serves (ReadPolicySet /
// MutationPolicySet); a table that is not in the supplied set is denied (fail
// closed), as is every table named in the explicit denied map. The engines are
// pure with respect to Appwrite: they validate, derive server-owned fields and
// build queries/ACLs, and the caller performs the actual list/create/update/
// delete. That keeps the security decisions testable without a network and lets
// any runtime adapter drive them. The package imports no OpenRuntimes or
// Function packages.
//
// Invariants enforced here and covered by the contract tests:
//
//   - the tenant is always the verified caller's team; a body organization_id
//     may only confirm it, and organization_id/$-fields are never client
//     writable;
//   - only allowlisted fields are accepted, with type, length, enum, numeric
//     and money validation; update-immutable and blocked fields are refused;
//   - a consumer-supplied reference fetcher can use RequireRowTenant so a
//     cross-tenant and a missing row are the same 404;
//   - reads inject the authoritative organization_id filter, reject any client
//     query naming organization_id, bound limit/offset/select, apply a field
//     projection plus a global credential deny list, and re-check every
//     returned row's tenant;
//   - created rows get read-only ACLs for the tenant's staff roles (and an
//     optional verified customer user); no update/delete/any/users grant.
package rows

// Operation is a gateway mutation.
type Operation string

const (
	OpCreate Operation = "create"
	OpUpdate Operation = "update"
	OpDelete Operation = "delete"
)

// Allow reports whether op is a known operation.
func (op Operation) Allow() bool {
	switch op {
	case OpCreate, OpUpdate, OpDelete:
		return true
	default:
		return false
	}
}

// Limits. They are part of the contract: tests pin them.
const (
	// MaxMutationFields bounds a single create/update body.
	MaxMutationFields = 64
	// MaxMutationBytes bounds the raw field JSON of one mutation.
	MaxMutationBytes = 64 * 1024
	// MaxArrayItems bounds an array field.
	MaxArrayItems = 50

	// MaxReadBodyBytes is the hard parse limit of a read request body.
	MaxReadBodyBytes = 32 * 1024
	// MaxReadQueries bounds the client query list.
	MaxReadQueries = 20
	// MaxReadQueryBytes bounds one client query string.
	MaxReadQueryBytes = 512
	// MaxReadSelectFields bounds the select projection.
	MaxReadSelectFields = 64
	// MaxReadSelectFieldBytes bounds one selected attribute name.
	MaxReadSelectFieldBytes = 64
	// DefaultReadLimit is the page size when the caller sends none.
	DefaultReadLimit = 50
	// MaxReadLimit is the hard page-size cap; larger values are clamped.
	MaxReadLimit = 100
	// MaxReadOffset caps the largest accepted offset.
	MaxReadOffset = 10000
)
