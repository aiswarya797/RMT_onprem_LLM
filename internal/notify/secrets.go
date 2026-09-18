package notify

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"rmt.local/monitor/internal/config"
)

var ErrSecretUnavailable = errors.New("notification secret unavailable")
var secretReference = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Vault stores immutable authenticated ciphertexts separately from the database.
// Its key is user-owned and included only in encrypted operational backups.
type Vault struct{ Dir, KeyFile string }

func (v Vault) key(create bool) ([]byte, error) {
	if create {
		if err := config.EnsurePrivateDir(v.Dir); err != nil {
			return nil, ErrSecretUnavailable
		}
		if _, err := os.Lstat(v.KeyFile); errors.Is(err, os.ErrNotExist) {
			entries, readErr := os.ReadDir(v.Dir)
			if readErr != nil {
				return nil, ErrSecretUnavailable
			}
			for _, entry := range entries {
				if secretReference.MatchString(entry.Name()) {
					return nil, ErrSecretUnavailable
				}
			}
			key := make([]byte, 32)
			if _, err = rand.Read(key); err != nil {
				return nil, ErrSecretUnavailable
			}
			if err = writeExclusive(v.KeyFile, key); err != nil && !errors.Is(err, os.ErrExist) {
				return nil, ErrSecretUnavailable
			}
		}
	}
	if config.ValidatePrivateFile(v.KeyFile) != nil {
		return nil, ErrSecretUnavailable
	}
	b, err := readSecretFile(v.KeyFile, 32)
	if err != nil || len(b) != 32 {
		return nil, ErrSecretUnavailable
	}
	return b, nil
}

// Fingerprint protects low-entropy submitted credentials from an offline
// dictionary attack against an idempotency receipt in a copied database.
func (v Vault) Fingerprint(data []byte) (string, error) {
	key, err := v.key(true)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func (v Vault) Put(scope, secret string) (string, error) {
	if len(secret) > 4096 || len(scope) == 0 || len(scope) > 4096 {
		return "", ErrSecretUnavailable
	}
	key, err := v.key(true)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("notification-secret-1\x00" + scope + "\x00" + secret))
	ref := hex.EncodeToString(mac.Sum(nil))
	if _, err := os.Lstat(filepath.Join(v.Dir, ref)); errors.Is(err, os.ErrNotExist) {
		d, err := os.Open(v.Dir)
		if err != nil {
			return "", ErrSecretUnavailable
		}
		names, readErr := d.Readdirnames(4098)
		d.Close()
		if (readErr != nil && !errors.Is(readErr, io.EOF)) || len(names) >= 4097 {
			return "", ErrSecretUnavailable
		}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", ErrSecretUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", ErrSecretUnavailable
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", ErrSecretUnavailable
	}
	envelope := append([]byte{1}, nonce...)
	envelope = aead.Seal(envelope, nonce, []byte(secret), []byte(ref))
	if err = writeExclusive(filepath.Join(v.Dir, ref), envelope); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return "", ErrSecretUnavailable
		}
		prior, err := v.Read(ref)
		if err != nil || !hmac.Equal([]byte(prior), []byte(secret)) {
			return "", ErrSecretUnavailable
		}
	}
	return ref, nil
}

func (v Vault) Read(ref string) (string, error) {
	if !secretReference.MatchString(ref) {
		return "", ErrSecretUnavailable
	}
	key, err := v.key(false)
	if err != nil {
		return "", err
	}
	path := filepath.Join(v.Dir, ref)
	if config.ValidatePrivateFile(path) != nil {
		return "", ErrSecretUnavailable
	}
	envelope, err := readSecretFile(path, 4125)
	if err != nil || len(envelope) < 29 || envelope[0] != 1 {
		return "", ErrSecretUnavailable
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", ErrSecretUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", ErrSecretUnavailable
	}
	plain, err := aead.Open(nil, envelope[1:13], envelope[13:], []byte(ref))
	if err != nil || len(plain) > 4096 {
		return "", ErrSecretUnavailable
	}
	return string(plain), nil
}

func readSecretFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, ErrSecretUnavailable
	}
	return b, nil
}

// A synchronized temporary inode is linked into place without overwriting an
// existing key/envelope. Concurrent exact retries share the durable winner.
func writeExclusive(path string, data []byte) error {
	if err := config.EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".secret-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = io.Copy(f, bytes.NewReader(data)); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Link(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
