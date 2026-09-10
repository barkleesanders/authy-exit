package migrate

import (
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"howett.net/plist"
	_ "modernc.org/sqlite"
)

var inventoryFields = []string{"_id", "name", "original_name", "original_issuer", "issuer", "username", "logo", "account_name", "account_type", "type", "digits", "keyDerivationIterations", "is_encrypted", "is_hidden"}

func InventoryFromPlist(b []byte) (Inventory, error) {
	out := Inventory{SourceSHA256: Hash(b), Accounts: []Record{}}
	var values map[string]any
	if _, err := plist.Unmarshal(b, &values); err != nil {
		return out, errors.New("invalid or encrypted Authy preferences plist")
	}
	for _, value := range values {
		r, ok := value.(map[string]any)
		if !ok || Text(r, "_id") == "" || Text(r, "name", "original_name") == "" {
			continue
		}
		safe := Record{}
		for _, k := range inventoryFields {
			if v, ok := r[k]; ok {
				safe[k] = v
			}
		}
		out.Accounts = append(out.Accounts, safe)
	}
	if len(out.Accounts) == 0 {
		return out, errors.New("no Authy account metadata found")
	}
	sort.Slice(out.Accounts, func(i, j int) bool { return ID(out.Accounts[i]) < ID(out.Accounts[j]) })
	return out, nil
}

// Read only the group preferences file identified by the backup manifest.
// This does not unlock encrypted Finder backups or copy unrelated app files.
func InventoryFromBackup(dir string) (Inventory, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return Inventory{}, errors.New("invalid backup path")
	}
	manifest := filepath.Join(abs, "Manifest.db")
	if _, err = os.Stat(manifest); err != nil {
		return Inventory{}, errors.New("backup must contain Manifest.db")
	}
	u := url.URL{Scheme: "file", Path: manifest, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return Inventory{}, errors.New("cannot open backup manifest")
	}
	defer db.Close()
	rows, err := db.Query("SELECT fileID FROM Files WHERE domain LIKE 'AppDomainGroup-group.authy.%' AND relativePath LIKE 'Library/Preferences/group.authy.%.plist' AND flags = 1")
	if err != nil {
		return Inventory{}, errors.New("cannot read manifest; encrypted backups must first be decrypted locally")
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return Inventory{}, errors.New("invalid manifest record")
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		return Inventory{}, errors.New("manifest read failed")
	}
	if len(ids) != 1 {
		return Inventory{}, errors.New("expected exactly one Authy group preferences file; supply --plist explicitly if ambiguous")
	}
	id := strings.ToLower(ids[0])
	if !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(id) {
		return Inventory{}, errors.New("invalid backup file ID")
	}
	b, err := Read(filepath.Join(abs, id[:2], id))
	if err != nil {
		return Inventory{}, err
	}
	return InventoryFromPlist(b)
}
