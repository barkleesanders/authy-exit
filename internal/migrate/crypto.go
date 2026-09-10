package migrate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

func Decrypt(r Record, password []byte) (string, error) {
	n, err := Integer(r, 0, "key_derivation_iterations", "keyDerivationIterations")
	if err != nil || n < 1 || n > 1000000 {
		return "", errors.New("unsupported KDF iterations (allowed 1..1000000)")
	}
	salt, _ := r["salt"].(string)
	if salt == "" {
		return "", errors.New("missing salt")
	}
	key, err := pbkdf2.Key(sha1.New, string(password), []byte(salt), n, 32)
	if err != nil {
		return "", errors.New("key derivation failed")
	}
	defer clear(key)
	iv := make([]byte, aes.BlockSize)
	if s := Text(r, "unique_iv"); s != "" {
		iv, err = hex.DecodeString(s)
		if err != nil || len(iv) != aes.BlockSize {
			return "", errors.New("invalid IV")
		}
	}
	encoded := strings.Join(strings.Fields(Text(r, "encrypted_seed")), "")
	ct, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(ct) == 0 || len(ct) > 4096 || len(ct)%aes.BlockSize != 0 {
		return "", errors.New("invalid ciphertext")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", errors.New("cipher initialization failed")
	}
	plain := make([]byte, len(ct))
	defer clear(plain)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ct)
	pad := int(plain[len(plain)-1])
	if pad < 1 || pad > aes.BlockSize {
		return "", errors.New("decryption failed: wrong backup password or damaged record")
	}
	for _, b := range plain[len(plain)-pad:] {
		if int(b) != pad {
			return "", errors.New("decryption failed: wrong backup password or damaged record")
		}
	}
	plain = plain[:len(plain)-pad]
	if !utf8.Valid(plain) {
		return "", errors.New("decrypted seed is not UTF-8")
	}
	secret := strings.TrimRight(strings.ToUpper(strings.TrimSpace(string(plain))), "=")
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	defer clear(seed)
	if err != nil || len(seed) < 10 || base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed) != secret {
		return "", errors.New("noncanonical or weak Base32 seed; explicit re-enrollment needed")
	}
	return secret, nil
}

func TOTP(secret string, digits int, counter uint64) (string, error) {
	if digits != 6 && digits != 8 {
		return "", errors.New("only 6 or 8 digit TOTP is supported")
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return "", errors.New("invalid Base32 seed")
	}
	defer clear(key)
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, counter)
	m := hmac.New(sha1.New, key)
	_, _ = m.Write(b)
	h := m.Sum(nil)
	offset := h[len(h)-1] & 15
	code := binary.BigEndian.Uint32(h[offset:offset+4]) & 0x7fffffff
	mod := uint32(1000000)
	if digits == 8 {
		mod = 100000000
	}
	return fmt.Sprintf("%0*d", digits, code%mod), nil
}

func OTPURI(e Entry, r Record, secret string) (string, error) {
	digits, err := Integer(r, 6, "digits")
	if err != nil || digits != 6 && digits != 8 {
		return "", errors.New("unsupported TOTP digits")
	}
	if a := strings.ToUpper(Text(r, "algorithm")); a != "" && a != "SHA1" {
		return "", errors.New("unsupported TOTP algorithm")
	}
	if period, err := Integer(r, 30, "period"); err != nil || period != 30 {
		return "", errors.New("unsupported TOTP period")
	}
	label := e.Name
	if e.Username != "" {
		label = e.Username
		if e.Issuer != "" {
			label = e.Issuer + ":" + e.Username
		}
	}
	q := url.Values{"secret": {secret}, "algorithm": {"SHA1"}, "digits": {strconv.Itoa(digits)}, "period": {"30"}}
	if e.Issuer != "" {
		q.Set("issuer", e.Issuer)
	}
	return "otpauth://totp/" + url.PathEscape(label) + "?" + q.Encode(), nil
}

func Export(c Capture, p Plan, password []byte) (map[string]any, error) {
	byID := map[string]Record{}
	for _, r := range c.Tokens {
		byID[ID(r)] = r
	}
	items := []any{}
	folder := "00000000-0000-4000-8000-000000000001"
	for i, e := range p.Entries {
		if e.Exclude {
			continue
		}
		r := byID[e.ID]
		if r == nil {
			return nil, SlotError(i, "no captured seed; exclude this entry or capture again")
		}
		secret, err := Decrypt(r, password)
		if err != nil {
			return nil, SlotError(i, err.Error())
		}
		uri, err := OTPURI(e, r, secret)
		if err != nil {
			return nil, SlotError(i, err.Error())
		}
		uris := []any{}
		for _, u := range e.URLs {
			uris = append(uris, map[string]any{"uri": u, "match": nil})
		}
		items = append(items, map[string]any{"type": 1, "name": e.Name + " — Authy " + e.ID, "folderId": folder, "favorite": false, "notes": "Imported with authy-exit. Source token ID: " + e.ID, "fields": []any{map[string]any{"name": SourceField, "value": e.ID, "type": 0}}, "login": map[string]any{"username": e.Username, "password": "", "totp": uri, "uris": uris}})
	}
	if len(items) == 0 {
		return nil, errors.New("no included tokens to export")
	}
	return map[string]any{"encrypted": false, "folders": []any{map[string]any{"id": folder, "name": "Verification codes"}}, "items": items}, nil
}
