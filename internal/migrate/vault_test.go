package migrate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeVault struct {
	items     []Record
	writes    int
	failAfter int
	changed   bool
	user      string
}

func (f *fakeVault) Call(args []string, input any, output any) error {
	var result any
	switch strings.Join(args[:min(2, len(args))], " ") {
	case "status":
		user := f.user
		if user == "" {
			user = "demo@example.invalid"
		}
		result = Record{"status": "unlocked", "userEmail": user, "serverUrl": "https://vault.example.invalid"}
	case "sync":
		return nil
	case "list items":
		result = f.items
	case "list folders":
		result = []Record{{"id": "folder", "name": "Verification codes"}}
	case "get item":
		for _, i := range f.items {
			if Text(i, "id") == args[2] {
				result = copyRecord(i)
				if f.changed {
					result.(Record)["notes"] = "concurrent change"
				}
			}
		}
		if result == nil {
			return errors.New("missing fake item")
		}
	case "create item", "edit item":
		if f.failAfter > 0 && f.writes >= f.failAfter {
			return errors.New("synthetic connection error")
		}
		f.writes++
		r := copyRecord(input.(Record))
		if args[0] == "create" {
			r["id"] = fmt.Sprintf("created-%d", f.writes)
			f.items = append(f.items, r)
		} else {
			for i, v := range f.items {
				if Text(v, "id") == args[2] {
					f.items[i] = r
				}
			}
		}
		result = r
	default:
		return errors.New("unexpected fake command")
	}
	if output != nil {
		b, _ := json.Marshal(result)
		return Decode(b, output)
	}
	return nil
}
func fixtureExport(t *testing.T) Record {
	t.Helper()
	r := encrypted(t, testSecret, "p", make([]byte, 16))
	c := Capture{Tokens: []Record{r}}
	p, _ := BuildPlan(c, "h", Inventory{})
	data, err := Export(c, p, []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	return normalized(t, data)
}
func opts(t *testing.T) VaultOptions {
	t.Helper()
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	return VaultOptions{User: "demo@example.invalid", Server: "https://vault.example.invalid", Receipt: filepath.Join(dir, "receipt.json"), Apply: true}
}
func target(t *testing.T) Record {
	return normalized(t, Record{"id": "target", "name": "Keep this name", "notes": "Keep notes", "folderId": "old", "login": Record{"password": "SYNTHETIC_PASSWORD", "username": "demo@example.invalid", "uris": []any{Record{"uri": "https://example.invalid"}}, "fido2Credentials": []any{Record{"credentialId": "synthetic-passkey"}}}, "passwordHistory": []any{Record{"password": "SYNTHETIC_HISTORY"}}, "fields": []any{Record{"name": "custom", "type": 0, "value": "keep"}}})
}
func TestApplyPreservesLoginAndRetries(t *testing.T) {
	before := target(t)
	v := &fakeVault{items: []Record{copyRecord(before)}}
	data := fixtureExport(t)
	o := opts(t)
	r, err := ApplyVault(v, data, map[string]string{"synthetic-1": "target"}, o)
	if err != nil || r.Attached != 1 {
		t.Fatal("attach failed", err)
	}
	after := v.items[0]
	if Text(login(after), "password") != Text(login(before), "password") || Text(after, "name") != Text(before, "name") || Text(after, "notes") != Text(before, "notes") {
		t.Fatal("preservation failed")
	}
	r, err = ApplyVault(v, data, map[string]string{"synthetic-1": "target"}, o)
	if err != nil || r.AlreadyPresent != 1 || v.writes != 1 {
		t.Fatal("retry duplicated write", err)
	}
	if _, err = os.Stat(o.Receipt); err != nil {
		t.Fatal("missing receipt")
	}
}
func TestApplyCreateIdempotent(t *testing.T) {
	v := &fakeVault{}
	data := fixtureExport(t)
	o := opts(t)
	r, err := ApplyVault(v, data, nil, o)
	if err != nil || r.Created != 1 {
		t.Fatal(err)
	}
	r, err = ApplyVault(v, data, nil, o)
	if err != nil || r.AlreadyPresent != 1 || v.writes != 1 {
		t.Fatal("create duplicated", err)
	}
}
func TestApplyFailsBeforeWrites(t *testing.T) {
	for _, scenario := range []string{"identity", "conflict", "changed", "dryrun", "missing-target", "receipt-exists"} {
		t.Run(scenario, func(t *testing.T) {
			v := &fakeVault{items: []Record{target(t)}}
			o := opts(t)
			targets := map[string]string{"synthetic-1": "target"}
			switch scenario {
			case "identity":
				v.user = "other@example.invalid"
			case "conflict":
				login(v.items[0])["totp"] = "OTHER_SECRET"
			case "changed":
				v.changed = true
			case "dryrun":
				o.Apply = false
			case "missing-target":
				targets["synthetic-1"] = "missing"
			case "receipt-exists":
				_ = os.WriteFile(o.Receipt, []byte("existing"), 0600)
			}
			_, err := ApplyVault(v, fixtureExport(t), targets, o)
			if scenario != "dryrun" && err == nil {
				t.Fatal("expected failure")
			}
			if v.writes != 0 {
				t.Fatal("unexpected write")
			}
		})
	}
}
