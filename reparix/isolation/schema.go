package isolation

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Column is one column of a db/*.yaml table definition.
type Column struct {
	Key      string
	Type     string
	Size     int
	Required bool
	Array    bool
	Elements []string
	Default  any
	HasDef   bool
}

// Index is one index of a table definition.
type Index struct {
	Key     string
	Type    string
	Columns []string
}

// Table is a parsed db/*.yaml table definition.
type Table struct {
	Name    string
	Columns []Column
	Indexes []Index
}

// Column returns the named column.
func (t *Table) Column(key string) (Column, bool) {
	for _, c := range t.Columns {
		if c.Key == key {
			return c, true
		}
	}
	return Column{}, false
}

// Tenant reports whether rows of the table belong to one organisation.
func (t *Table) Tenant() bool {
	_, ok := t.Column("organization_id")
	return ok
}

// LoadSchema parses every table file in dir (Reparix's db/ folder). Only the
// regular subset of YAML the schema files use is understood.
func LoadSchema(dir string) (map[string]*Table, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	out := map[string]*Table{}
	for _, file := range files {
		if strings.HasPrefix(filepath.Base(file), "_") {
			continue
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		table, err := parseTable(string(raw))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(file), err)
		}
		if table.Name != "" {
			out[table.Name] = table
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no table definitions in %s", dir)
	}
	return out, nil
}

func parseTable(text string) (*Table, error) {
	t := &Table{}
	section := ""
	var col *Column
	var idx *Index
	inElements := false
	for _, raw := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		if indent == 0 {
			key, value, _ := strings.Cut(trimmed, ":")
			section = key
			if key == "table" {
				t.Name = unquote(strings.TrimSpace(value))
			}
			col, idx, inElements = nil, nil, false
			continue
		}
		if strings.HasPrefix(trimmed, "- key:") {
			key := unquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "- key:")))
			inElements = false
			switch section {
			case "columns":
				t.Columns = append(t.Columns, Column{Key: key})
				col, idx = &t.Columns[len(t.Columns)-1], nil
			case "indexes":
				t.Indexes = append(t.Indexes, Index{Key: key})
				idx, col = &t.Indexes[len(t.Indexes)-1], nil
			}
			continue
		}
		if inElements && strings.HasPrefix(trimmed, "- ") && col != nil {
			col.Elements = append(col.Elements, unquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))))
			continue
		}
		inElements = false
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch {
		case col != nil:
			switch key {
			case "type":
				col.Type = value
			case "size":
				col.Size, _ = strconv.Atoi(value)
			case "required":
				col.Required = value == "true"
			case "array":
				col.Array = value == "true"
			case "elements":
				if strings.HasPrefix(value, "[") {
					for _, e := range strings.Split(strings.Trim(value, "[]"), ",") {
						if e = unquote(strings.TrimSpace(e)); e != "" {
							col.Elements = append(col.Elements, e)
						}
					}
				} else {
					inElements = true
				}
			case "default":
				col.HasDef = true
				col.Default = scalar(value)
			}
		case idx != nil:
			switch key {
			case "type":
				idx.Type = value
			case "columns":
				for _, c := range strings.Split(strings.Trim(value, "[]"), ",") {
					if c = unquote(strings.TrimSpace(c)); c != "" {
						idx.Columns = append(idx.Columns, c)
					}
				}
			}
		}
	}
	return t, nil
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

func scalar(v string) any {
	switch v {
	case "null", "~":
		return nil
	case "true":
		return true
	case "false":
		return false
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return n
	}
	if f, err := strconv.ParseFloat(v, 64); err == nil {
		return f
	}
	return unquote(v)
}

func sortedNames(tables map[string]*Table) []string {
	names := make([]string, 0, len(tables))
	for name := range tables {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
