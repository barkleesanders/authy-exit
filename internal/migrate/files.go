package migrate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const MaxInput = 32 << 20

func Read(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open input file")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxInput+1))
	if err != nil || len(b) > MaxInput {
		return nil, errors.New("input unreadable or larger than 32 MiB")
	}
	return b, nil
}

func Hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// WriteNew never overwrites an existing file, including a symlink. A private
// directory is required because metadata, too, can reveal account identities.
func WriteNew(path string, value any) error {
	if path == "" || path == "-" {
		return errors.New("an output file is required; stdout export is disabled")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("cannot create output directory")
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("output directory must be private (chmod 700)")
	}
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return errors.New("cannot encode output")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot create output; choose a new filename")
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err = f.Write(append(b, '\n')); err != nil {
		return errors.New("cannot write output")
	}
	if err = f.Sync(); err != nil {
		return errors.New("cannot sync output")
	}
	if err = f.Close(); err != nil {
		return errors.New("cannot close output")
	}
	ok = true
	return nil
}
