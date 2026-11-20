package apptest

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type parsedQuery struct {
	Method    string            `json:"method"`
	Attribute string            `json:"attribute"`
	Values    []json.RawMessage `json:"values"`
}

func (q parsedQuery) value(i int) any {
	if i >= len(q.Values) {
		return nil
	}
	var v any
	_ = json.Unmarshal(q.Values[i], &v)
	return v
}

func (q parsedQuery) values() []any {
	out := make([]any, 0, len(q.Values))
	for i := range q.Values {
		out = append(out, q.value(i))
	}
	return out
}

func (q parsedQuery) subQueries() ([]parsedQuery, *apiError) {
	var out []parsedQuery
	for _, raw := range q.Values {
		var sub parsedQuery
		if err := json.Unmarshal(raw, &sub); err != nil {
			// Values may also be JSON strings holding a query.
			var s string
			if json.Unmarshal(raw, &s) != nil || json.Unmarshal([]byte(s), &sub) != nil {
				return nil, errorf(400, "general_query_invalid", "invalid nested query")
			}
		}
		out = append(out, sub)
	}
	return out, nil
}

func parseQueries(raw []string) ([]parsedQuery, *apiError) {
	out := make([]parsedQuery, 0, len(raw))
	for _, r := range raw {
		var q parsedQuery
		if err := json.Unmarshal([]byte(r), &q); err != nil || q.Method == "" {
			return nil, errorf(400, "general_query_invalid", "invalid query: %s", r)
		}
		out = append(out, q)
	}
	return out, nil
}

func withoutPaging(raw []string) []string {
	qs, err := parseQueries(raw)
	if err != nil {
		return raw
	}
	var out []string
	for i, q := range qs {
		switch q.Method {
		case "limit", "offset", "cursorAfter", "cursorBefore":
			continue
		}
		out = append(out, raw[i])
	}
	return out
}

// applyQueries filters, orders, pages and projects rows the way Appwrite does
// for the query methods this library uses. It returns the page and the total
// number of matching rows before paging.
func applyQueries(rows []Row, raw []string) ([]Row, int, *apiError) {
	qs, err := parseQueries(raw)
	if err != nil {
		return nil, 0, err
	}
	limit, offset := 25, 0
	var orders []parsedQuery
	var selects []string
	var cursor, cursorBefore string
	var filters []parsedQuery
	for _, q := range qs {
		switch q.Method {
		case "limit":
			if n, ok := toFloat(q.value(0)); ok {
				limit = int(n)
			}
		case "offset":
			if n, ok := toFloat(q.value(0)); ok {
				offset = int(n)
			}
		case "orderAsc", "orderDesc", "orderRandom":
			orders = append(orders, q)
		case "select":
			for _, v := range q.values() {
				selects = append(selects, fmt.Sprint(v))
			}
		case "cursorAfter":
			cursor = fmt.Sprint(q.value(0))
		case "cursorBefore":
			cursorBefore = fmt.Sprint(q.value(0))
		default:
			filters = append(filters, q)
		}
	}

	var matched []Row
	for _, row := range rows {
		ok := true
		for _, f := range filters {
			m, err := matches(row, f)
			if err != nil {
				return nil, 0, err
			}
			if !m {
				ok = false
				break
			}
		}
		if ok {
			matched = append(matched, row)
		}
	}

	if len(orders) > 0 {
		sort.SliceStable(matched, func(i, j int) bool {
			for _, o := range orders {
				if o.Method == "orderRandom" {
					continue
				}
				c := compare(matched[i][o.Attribute], matched[j][o.Attribute])
				if c == 0 {
					continue
				}
				if o.Method == "orderDesc" {
					return c > 0
				}
				return c < 0
			}
			return false
		})
	}
	total := len(matched)

	if cursor != "" {
		idx := indexOf(matched, cursor)
		if idx < 0 {
			return nil, 0, errorf(400, "general_cursor_not_found", "cursor row %s not found", cursor)
		}
		matched = matched[idx+1:]
	}
	if cursorBefore != "" {
		idx := indexOf(matched, cursorBefore)
		if idx < 0 {
			return nil, 0, errorf(400, "general_cursor_not_found", "cursor row %s not found", cursorBefore)
		}
		start := idx - limit
		if start < 0 {
			start = 0
		}
		matched = matched[start:idx]
	}
	if offset > len(matched) {
		offset = len(matched)
	}
	matched = matched[offset:]
	if limit >= 0 && limit < len(matched) {
		matched = matched[:limit]
	}

	out := make([]Row, 0, len(matched))
	for _, row := range matched {
		out = append(out, project(row, selects))
	}
	return out, total, nil
}

func indexOf(rows []Row, id string) int {
	for i, row := range rows {
		if row["$id"] == id {
			return i
		}
	}
	return -1
}

func project(row Row, selects []string) Row {
	if len(selects) == 0 {
		return row
	}
	for _, s := range selects {
		if s == "*" {
			return row
		}
	}
	out := Row{}
	for k, v := range row {
		if strings.HasPrefix(k, "$") {
			out[k] = v
		}
	}
	for _, s := range selects {
		if v, ok := row[s]; ok {
			out[s] = v
		}
	}
	return out
}

func matches(row Row, q parsedQuery) (bool, *apiError) {
	field, present := row[q.Attribute]
	switch q.Method {
	case "and", "or":
		subs, err := q.subQueries()
		if err != nil {
			return false, err
		}
		for _, sub := range subs {
			m, err := matches(row, sub)
			if err != nil {
				return false, err
			}
			if q.Method == "or" && m {
				return true, nil
			}
			if q.Method == "and" && !m {
				return false, nil
			}
		}
		return q.Method == "and", nil
	case "isNull":
		return !present || field == nil, nil
	case "isNotNull":
		return present && field != nil, nil
	case "equal":
		return anyElement(field, func(v any) bool {
			for _, want := range q.values() {
				if compare(v, want) == 0 && v != nil {
					return true
				}
			}
			return false
		}), nil
	case "notEqual":
		for _, want := range q.values() {
			if field != nil && compare(field, want) == 0 {
				return false, nil
			}
		}
		return true, nil
	case "lessThan", "lessThanEqual", "greaterThan", "greaterThanEqual":
		if field == nil {
			return false, nil
		}
		c := compare(field, q.value(0))
		switch q.Method {
		case "lessThan":
			return c < 0, nil
		case "lessThanEqual":
			return c <= 0, nil
		case "greaterThan":
			return c > 0, nil
		default:
			return c >= 0, nil
		}
	case "between", "notBetween":
		in := field != nil && compare(field, q.value(0)) >= 0 && compare(field, q.value(1)) <= 0
		return in == (q.Method == "between"), nil
	case "startsWith", "notStartsWith":
		s, _ := field.(string)
		ok := field != nil && strings.HasPrefix(s, fmt.Sprint(q.value(0)))
		return ok == (q.Method == "startsWith"), nil
	case "endsWith", "notEndsWith":
		s, _ := field.(string)
		ok := field != nil && strings.HasSuffix(s, fmt.Sprint(q.value(0)))
		return ok == (q.Method == "endsWith"), nil
	case "contains", "notContains", "containsAny":
		ok := false
		for _, want := range q.values() {
			switch f := field.(type) {
			case string:
				if strings.Contains(f, fmt.Sprint(want)) {
					ok = true
				}
			case []any:
				for _, item := range f {
					if compare(item, want) == 0 {
						ok = true
					}
				}
			}
		}
		return ok == (q.Method != "notContains"), nil
	case "search", "notSearch":
		s := strings.ToLower(fmt.Sprint(field))
		ok := false
		for _, word := range strings.Fields(strings.ToLower(fmt.Sprint(q.value(0)))) {
			if field != nil && strings.Contains(s, strings.Trim(word, `"*`)) {
				ok = true
			}
		}
		return ok == (q.Method == "search"), nil
	case "createdBefore", "createdAfter", "updatedBefore", "updatedAfter":
		key := "$createdAt"
		if strings.HasPrefix(q.Method, "updated") {
			key = "$updatedAt"
		}
		c := compare(row[key], q.value(0))
		if strings.HasSuffix(q.Method, "Before") {
			return c < 0, nil
		}
		return c > 0, nil
	case "createdBetween", "updatedBetween":
		key := "$createdAt"
		if q.Method == "updatedBetween" {
			key = "$updatedAt"
		}
		return compare(row[key], q.value(0)) >= 0 && compare(row[key], q.value(1)) <= 0, nil
	}
	return false, errorf(400, "apptest_query_unsupported", "apptest does not support query method %q", q.Method)
}

func anyElement(field any, fn func(any) bool) bool {
	if list, ok := field.([]any); ok {
		for _, item := range list {
			if fn(item) {
				return true
			}
		}
		return false
	}
	return fn(field)
}

// compare orders two JSON values: numbers numerically, everything else by
// its string form. nil sorts first.
func compare(a, b any) int {
	if a == nil && b == nil {
		return 0
	}
	if a == nil {
		return -1
	}
	if b == nil {
		return 1
	}
	_, aStr := a.(string)
	_, bStr := b.(string)
	if !aStr && !bStr {
		af, aok := toFloat(a)
		bf, bok := toFloat(b)
		if aok && bok {
			switch {
			case af < bf:
				return -1
			case af > bf:
				return 1
			}
			return 0
		}
	}
	as, bs := fmt.Sprint(a), fmt.Sprint(b)
	switch {
	case as < bs:
		return -1
	case as > bs:
		return 1
	}
	return 0
}
