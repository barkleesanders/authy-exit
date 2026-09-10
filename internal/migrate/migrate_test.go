package migrate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"howett.net/plist"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Public RFC 6238 SHA-1 test secret. Never use any fixture secret for an account.
const testSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // gitleaks:allow -- public RFC 6238 test vector

func encrypted(t *testing.T, secret, pw string, iv []byte) Record {
	t.Helper()
	key, err := pbkdf2.Key(sha1.New, pw, []byte("synthetic-salt"), 1000, 32)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(key)
	b := []byte(secret)
	pad := 16 - len(b)%16
	for i := 0; i < pad; i++ {
		b = append(b, byte(pad))
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(b, b)
	return Record{"unique_id": "synthetic-1", "name": "Example", "original_name": "Example:demo@example.invalid", "account_name": "Generic Blue", "logo": "example", "salt": "synthetic-salt", "unique_iv": hex.EncodeToString(iv), "key_derivation_iterations": 1000, "encrypted_seed": base64.StdEncoding.EncodeToString(b), "digits": 6}
}
func normalized(t *testing.T, v any) Record {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var r Record
	if err = Decode(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRFC6238(t *testing.T) {
	for _, v := range []struct {
		time uint64
		want string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"}} {
		got, err := TOTP(testSecret, 8, v.time/30)
		if err != nil || got != v.want {
			t.Fatalf("RFC vector failed at %d", v.time)
		}
	}
}
func TestDecryptAndFailures(t *testing.T) {
	for _, iv := range [][]byte{make([]byte, 16), []byte("synthetic-iv-123")} {
		r := encrypted(t, testSecret, "fixture-password", iv)
		got, err := Decrypt(r, []byte("fixture-password"))
		if err != nil || got != testSecret {
			t.Fatal("decrypt failed", err)
		}
		if _, err = Decrypt(r, []byte("wrong")); err == nil {
			t.Fatal("accepted wrong password")
		}
	}
	for _, secret := range []string{"A0B1C8", "MY", testSecret + "A", ""} {
		r := encrypted(t, secret, "p", make([]byte, 16))
		if _, err := Decrypt(r, []byte("p")); err == nil {
			t.Fatal("accepted malformed or weak seed")
		}
	}
	for _, change := range []Record{{"unique_iv": "ab"}, {"encrypted_seed": "AAA="}, {"key_derivation_iterations": 1000001}, {"key_derivation_iterations": 0}} {
		r := encrypted(t, testSecret, "p", make([]byte, 16))
		for k, v := range change {
			r[k] = v
		}
		if _, err := Decrypt(r, []byte("p")); err == nil {
			t.Fatal("accepted malformed envelope")
		}
	}
}
func TestMetadataNeverUsesTheme(t *testing.T) {
	c := Capture{Tokens: []Record{{"unique_id": "1", "name": "Nickname", "account_name": "Generic Blue"}, {"unique_id": "2", "name": "Nickname", "original_name": ""}}}
	inv := Inventory{Accounts: []Record{{"_id": "1", "logo": "service-logo", "original_name": "Issuer:user%40example.invalid"}, {"_id": "3", "name": "Managed"}}}
	p, err := BuildPlan(c, "digest", inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 3 || p.Entries[0].Username != "user@example.invalid" || p.Entries[0].Logo != "service-logo" || p.Entries[1].Username != "" || p.Entries[2].HasCapture {
		t.Fatal("metadata handling failed")
	}
}
func TestPlanBindingAndOmissions(t *testing.T) {
	r := encrypted(t, testSecret, "p", make([]byte, 16))
	c := Capture{Tokens: []Record{r}}
	p, _ := BuildPlan(c, "digest", Inventory{})
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	path := filepath.Join(dir, "plan.json")
	b, _ := json.Marshal(p)
	_ = os.WriteFile(path, b, 0600)
	if _, err := ReadPlan(path, "digest", c); err == nil {
		t.Fatal("unreviewed accepted")
	}
	p.Entries[0].Reviewed = true
	b, _ = json.Marshal(p)
	_ = os.WriteFile(path, b, 0600)
	if _, err := ReadPlan(path, "other", c); err == nil {
		t.Fatal("wrong capture accepted")
	}
	if _, err := ReadPlan(path, "digest", c); err != nil {
		t.Fatal(err)
	}
	p.Entries = nil
	b, _ = json.Marshal(p)
	_ = os.WriteFile(path, b, 0600)
	if _, err := ReadPlan(path, "digest", c); err == nil {
		t.Fatal("omission accepted")
	}
}
func TestExportAllOrNothing(t *testing.T) {
	a := encrypted(t, testSecret, "p", make([]byte, 16))
	b := encrypted(t, testSecret, "other", make([]byte, 16))
	b["unique_id"] = "synthetic-2"
	c := Capture{Tokens: []Record{a, b}}
	p, _ := BuildPlan(c, "h", Inventory{})
	if data, err := Export(c, p, []byte("p")); err == nil || data != nil {
		t.Fatal("partial result escaped")
	}
	p.Entries[1].Exclude = true
	data, err := Export(c, p, []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	r := normalized(t, data)
	item := r["items"].([]any)[0].(map[string]any)
	if sourceID(item) != "synthetic-1" || Text(login(item), "username") != "demo@example.invalid" || !strings.HasPrefix(Text(login(item), "totp"), "otpauth://totp/") {
		t.Fatal("invalid export")
	}
}
func TestPrivateOutput(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	path := filepath.Join(dir, "export.json")
	if err := WriteNew(path, Record{"test": true}); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("not private")
	}
	if err := WriteNew(path, Record{}); err == nil {
		t.Fatal("overwritten")
	}
	link := filepath.Join(dir, "symlink")
	_ = os.Symlink(path, link)
	if err := WriteNew(link, Record{}); err == nil {
		t.Fatal("followed symlink")
	}
	_ = os.Chmod(dir, 0755)
	if err := WriteNew(filepath.Join(dir, "bad"), Record{}); err == nil {
		t.Fatal("accepted public directory")
	}
}
func TestInventoryWhitelistAndManifest(t *testing.T) {
	values := map[string]any{"123": map[string]any{"_id": "123", "name": "Example", "logo": "demo", "session_token": "DO_NOT_EXPORT", "encrypted_seed": "DO_NOT_EXPORT"}, "session": "DO_NOT_EXPORT"}
	b, err := plist.Marshal(values, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := InventoryFromPlist(b)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(inv)
	if strings.Contains(string(encoded), "DO_NOT_EXPORT") || len(inv.Accounts) != 1 {
		t.Fatal("whitelist failed")
	}
	dir := t.TempDir()
	id := strings.Repeat("a", 40)
	_ = os.Mkdir(filepath.Join(dir, "aa"), 0700)
	_ = os.WriteFile(filepath.Join(dir, "aa", id), b, 0600)
	db, err := sql.Open("sqlite", filepath.Join(dir, "Manifest.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("CREATE TABLE Files(fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER)")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO Files VALUES(?,?,?,1)", id, "AppDomainGroup-group.authy.example", "Library/Preferences/group.authy.example.plist")
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	got, err := InventoryFromBackup(dir)
	if err != nil || len(got.Accounts) != 1 {
		t.Fatal("manifest extraction failed", err)
	}
}
