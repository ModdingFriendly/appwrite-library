package rows

import "github.com/ModdingFriendly/appwrite-library/reparix/tenant"

// TeamReadACL builds read-only row permissions: one read("team:<id>/<role>")
// per role plus one read("user:<id>") per user id. Invalid ids and duplicates
// are dropped; an invalid team yields an empty (non-nil) slice, never a broader
// grant. There is deliberately no update/delete/write, any, users or guest
// grant: row ACLs cannot constrain which fields a client changes.
func TeamReadACL(teamID string, roles []string, userIDs ...string) []string {
	if !tenant.ValidID(teamID) {
		return []string{}
	}
	acl := []string{}
	seen := map[string]struct{}{}
	add := func(perm string) {
		if _, dup := seen[perm]; !dup {
			seen[perm] = struct{}{}
			acl = append(acl, perm)
		}
	}
	for _, role := range roles {
		if tenant.ValidID(role) {
			add(`read("team:` + teamID + `/` + role + `")`)
		}
	}
	for _, id := range userIDs {
		if tenant.ValidID(id) {
			add(`read("user:` + id + `")`)
		}
	}
	return acl
}
