package migrate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

type Record map[string]any
type Capture struct {
	Tokens []Record `json:"authenticator_tokens"`
}
type Inventory struct {
	SourceSHA256 string   `json:"source_sha256"`
	Accounts     []Record `json:"accounts"`
}
type Entry struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Issuer     string   `json:"issuer"`
	Username   string   `json:"username"`
	Logo       string   `json:"logo,omitempty"`
	Theme      string   `json:"theme_not_username,omitempty"`
	URLs       []string `json:"urls"`
	Reviewed   bool     `json:"reviewed"`
	Exclude    bool     `json:"exclude"`
	HasCapture bool     `json:"has_capture"`
	Warnings   []string `json:"warnings"`
}
type Plan struct {
	Version         int     `json:"version"`
	CaptureSHA256   string  `json:"capture_sha256"`
	InventorySHA256 string  `json:"inventory_sha256,omitempty"`
	Entries         []Entry `json:"entries"`
}

func Text(r Record, keys ...string) string {
	for _, k := range keys {
		switch v := r[k].(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		case json.Number:
			return string(v)
		case uint64:
			return strconv.FormatUint(v, 10)
		case int64:
			return strconv.FormatInt(v, 10)
		case int:
			return strconv.Itoa(v)
		}
	}
	return ""
}
func ID(r Record) string { return Text(r, "unique_id", "token_id", "_id", "id") }
func Decode(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(v); err != nil {
		return errors.New("invalid JSON input")
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("unexpected trailing JSON data")
	}
	return nil
}

func ReadCapture(path string) (Capture, string, error) {
	b, err := Read(path)
	if err != nil {
		return Capture{}, "", err
	}
	var c Capture
	if err = Decode(b, &c); err != nil {
		return c, "", err
	}
	if len(c.Tokens) == 0 || len(c.Tokens) > 1000 {
		return c, "", errors.New("capture must contain 1 to 1000 authenticator tokens")
	}
	seen := map[string]bool{}
	for _, r := range c.Tokens {
		id := ID(r)
		if id == "" || seen[id] {
			return c, "", errors.New("missing or duplicate capture ID")
		}
		seen[id] = true
	}
	return c, Hash(b), nil
}

func BuildPlan(c Capture, hash string, inv Inventory) (Plan, error) {
	p := Plan{Version: 1, CaptureSHA256: hash, Entries: []Entry{}}
	records := map[string]Record{}
	captured := map[string]bool{}
	for _, r := range inv.Accounts {
		id := ID(r)
		if id == "" || records[id] != nil {
			return p, errors.New("missing or duplicate inventory ID")
		}
		records[id] = r
	}
	for _, r := range c.Tokens {
		id := ID(r)
		base := Record{}
		for k, v := range records[id] {
			base[k] = v
		}
		for k, v := range r {
			if v != nil && v != "" {
				base[k] = v
			}
		}
		records[id] = base
		captured[id] = true
	}
	for id, r := range records {
		original := Text(r, "original_name")
		name := Text(r, "name", "original_name")
		issuer := Text(r, "issuer", "original_issuer")
		username := Text(r, "username")
		warnings := []string{}
		if username == "" {
			if _, account, ok := strings.Cut(original, ":"); ok {
				username = account
				warnings = append(warnings, "label account is a candidate; confirm it is a login identifier")
			} else if strings.Contains(original, "@") {
				username = original
			}
		}
		if decoded, err := url.PathUnescape(username); err == nil {
			username = decoded
		}
		username = strings.TrimSpace(username)
		if issuer == "" {
			if label, _, ok := strings.Cut(original, ":"); ok {
				issuer = label
			}
		}
		if name == "" {
			name = "Authy account " + id
		}
		if username == "" {
			warnings = append(warnings, "username unknown; theme was not used")
		}
		warnings = append(warnings, "website needs review; logo is evidence, not an automatic match")
		if !captured[id] {
			warnings = append(warnings, "no encrypted seed captured; unsupported managed token or incomplete sync")
		}
		p.Entries = append(p.Entries, Entry{ID: id, Name: name, Issuer: issuer, Username: username, Logo: Text(r, "logo"), Theme: Text(r, "account_name"), URLs: []string{}, HasCapture: captured[id], Warnings: warnings})
	}
	sort.Slice(p.Entries, func(i, j int) bool { return p.Entries[i].ID < p.Entries[j].ID })
	labels := map[string]int{}
	for _, e := range p.Entries {
		labels[strings.ToLower(e.Name+"\x00"+e.Username)]++
	}
	for i, e := range p.Entries {
		if labels[strings.ToLower(e.Name+"\x00"+e.Username)] > 1 {
			p.Entries[i].Warnings = append(e.Warnings, "duplicate label; retained as a distinct token ID")
		}
	}
	return p, nil
}

func ReadPlan(path, captureHash string, c Capture) (Plan, error) {
	b, err := Read(path)
	if err != nil {
		return Plan{}, err
	}
	var p Plan
	if err = Decode(b, &p); err != nil {
		return p, err
	}
	if p.Version != 1 || p.CaptureSHA256 != captureHash {
		return p, errors.New("plan version or capture digest mismatch; rebuild the plan")
	}
	seen := map[string]bool{}
	for _, e := range p.Entries {
		if e.ID == "" || seen[e.ID] {
			return p, errors.New("duplicate or missing plan ID")
		}
		seen[e.ID] = true
		if e.Exclude {
			continue
		}
		if !e.Reviewed {
			return p, errors.New("every included entry must be reviewed; exclude unsupported accounts explicitly")
		}
		if strings.TrimSpace(e.Name) == "" {
			return p, errors.New("included entry has no name")
		}
		for _, s := range e.URLs {
			u, err := url.Parse(s)
			if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
				return p, errors.New("websites must be HTTPS URLs without credentials, queries or fragments")
			}
		}
	}
	for _, r := range c.Tokens {
		if !seen[ID(r)] {
			return p, errors.New("plan omitted a capture ID; use exclude instead of deleting entries")
		}
	}
	return p, nil
}

func Integer(r Record, fallback int, keys ...string) (int, error) {
	s := Text(r, keys...)
	if s == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, errors.New("invalid numeric token field")
	}
	return n, nil
}

func Summary(p Plan) map[string]any {
	captured, excluded, reviewed := 0, 0, 0
	for _, e := range p.Entries {
		if e.HasCapture {
			captured++
		}
		if e.Exclude {
			excluded++
		}
		if e.Reviewed {
			reviewed++
		}
	}
	return map[string]any{"accounts": len(p.Entries), "captured": captured, "without_capture": len(p.Entries) - captured, "excluded": excluded, "reviewed": reviewed}
}

func SlotError(i int, reason string) error { return fmt.Errorf("record %d: %s", i+1, reason) }
