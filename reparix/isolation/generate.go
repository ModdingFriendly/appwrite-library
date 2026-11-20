package isolation

import (
	"regexp"
	"strings"
)

var (
	moneyKey    = regexp.MustCompile(`(^|_)(amount|total|subtotal|price|cost|tax|balance|fee|deposit|discount|value|rate|margin|profit|paid|due|refund|tip|change|float|expected|counted|variance|spend|revenue|credit|debit)(_|$)`)
	quantityKey = regexp.MustCompile(`(^|_)(qty|quantity|count|stock|points)(_|$)`)
	dateKey     = regexp.MustCompile(`(_at|_date|^date|_on|_until|_from|_to|_time)$`)
	jsonKey     = regexp.MustCompile(`(json|settings|config|filters|stages|templates|payload|meta|metadata|changes|options|schedule|layout|widgets|items|lines|data|facts|context|details|answers|results|checks)$`)
	userKey     = regexp.MustCompile(`(^|_)user_id$`)
)

const fixedTime = "2026-01-01T09:00:00.000+00:00"

// generate builds one plausible row of table for org from its schema. Text
// values carry org's canary; references point at org's own seeded rows.
func (f *Fixture) generate(org Org, table *Table) map[string]any {
	row := map[string]any{}
	for _, c := range table.Columns {
		v := f.value(org, table, c)
		if v == nil {
			continue
		}
		if c.Array {
			v = []any{v}
		}
		row[c.Key] = v
	}
	return row
}

func (f *Fixture) value(org Org, table *Table, c Column) any {
	key := c.Key
	switch {
	case key == "organization_id" || key == "team_id":
		return org.TeamID
	case userKey.MatchString(key):
		if strings.Contains(key, "customer") || strings.HasPrefix(table.Name, "customer") || strings.HasPrefix(table.Name, "portal") {
			return org.Users[RoleCustomer]
		}
		return org.Users[RoleAdmin]
	}
	switch c.Type {
	case "enum":
		if c.HasDef && c.Default != nil && c.Default != "" {
			return c.Default
		}
		if len(c.Elements) > 0 {
			return c.Elements[0]
		}
		return nil
	case "integer":
		if c.HasDef && c.Default != nil {
			return c.Default
		}
		return int64(1)
	case "double", "float":
		if c.HasDef && c.Default != nil {
			return c.Default
		}
		return 1.0
	case "boolean":
		if c.HasDef && c.Default != nil {
			return c.Default
		}
		return false
	case "datetime":
		// An optional timestamp usually marks a state change (deleted_at,
		// revoked_at, merged_at), so it stays unset.
		if !c.Required {
			return nil
		}
		return fixedTime
	case "email":
		return org.Canary + "@example.test"
	}

	// String-like columns.
	if strings.HasSuffix(key, "_id") {
		if ref, ok := f.reference(org, strings.TrimSuffix(key, "_id")); ok {
			return ref
		}
		if !c.Required {
			return nil
		}
		return fit(org.Key+"-"+key, c.Size)
	}
	if c.HasDef && c.Default != nil && c.Default != "" {
		return c.Default
	}
	switch {
	case strings.Contains(key, "currency"):
		return "GBP"
	case moneyKey.MatchString(key):
		// Reparix stores money as a canonical "<CUR> <amount>" string.
		return "GBP 10.00"
	case quantityKey.MatchString(key):
		return "1"
	case strings.Contains(key, "email"):
		return fit(org.Canary+"@example.test", c.Size)
	case strings.Contains(key, "phone") || strings.Contains(key, "mobile"):
		return "+447700900123"
	case dateKey.MatchString(key):
		if !c.Required {
			return nil
		}
		return fixedTime
	case strings.HasSuffix(key, "_reason") && !c.Required:
		// Like an optional timestamp, a reason records a state change
		// (revoke_reason, void_reason), so it stays unset.
		return nil
	case key == "status" || key == "state":
		return "open"
	case jsonKey.MatchString(key):
		if !c.Required {
			return nil
		}
		return "{}"
	}
	if c.Size > 0 && c.Size < len(org.Canary)+1 {
		return fit(org.Key, c.Size)
	}
	return fit(org.Canary+" "+key, c.Size)
}

// reference resolves "<name>_id" to org's seeded row of the matching table.
func (f *Fixture) reference(org Org, name string) (string, bool) {
	candidates := []string{name + "s", name + "es", name, strings.TrimSuffix(name, "y") + "ies"}
	if i := strings.LastIndex(name, "_"); i >= 0 {
		tail := name[i+1:]
		candidates = append(candidates, tail+"s", tail+"es", tail)
	}
	for _, c := range candidates {
		if id, ok := org.IDs[c]; ok {
			return id, true
		}
	}
	return "", false
}

func fit(s string, size int) string {
	if size > 0 && len(s) > size {
		return s[:size]
	}
	return s
}
