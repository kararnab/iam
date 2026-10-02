package password

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/kararnab/iam/v2"
	"github.com/kararnab/iam/v2/provider"
)

// creds is a minimal CredentialStore (memstore imports this package).
type creds map[string]string

func (c creds) GetCredential(_ context.Context, l string) (string, error) {
	if h, ok := c[l]; ok {
		return h, nil
	}
	return "", iam.ErrNotFound
}
func (c creds) CreateCredential(_ context.Context, l, h string) error {
	if _, ok := c[l]; ok {
		return iam.ErrConflict
	}
	c[l] = h
	return nil
}
func (c creds) UpdateCredential(_ context.Context, l, h string) error { c[l] = h; return nil }
func (c creds) DeleteCredential(_ context.Context, l string) error    { delete(c, l); return nil }

// countingHasher records Verify calls to check the unknown-login path.
type countingHasher struct {
	Hasher
	verifies int
}

func (c *countingHasher) Verify(ctx context.Context, pw, enc string) (bool, error) {
	c.verifies++
	return c.Hasher.Verify(ctx, pw, enc)
}

func TestProvider(t *testing.T) {
	ctx := context.Background()
	store := creds{}
	h := &countingHasher{Hasher: newHasher(t, fast)}
	p, err := NewProvider(store, h, Policy{})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := p.Register(ctx, map[string]string{"username": "Alice@Example.com", "password": "short"}); !errors.Is(err, ErrTooShort) {
		t.Fatalf("short password: %v", err)
	}
	id, err := p.Register(ctx, map[string]string{"username": "Alice@Example.com", "password": "long enough password"})
	if err != nil || id.ProviderID != "alice@example.com" || id.EmailVerified {
		t.Fatalf("register: %v %+v", err, id)
	}
	if _, err := p.Register(ctx, map[string]string{"username": "alice@example.com", "password": "long enough password"}); !errors.Is(err, iam.ErrConflict) {
		t.Fatalf("duplicate register: %v", err)
	}

	tests := []struct {
		name       string
		user, pw   string
		ok         bool
		wantVerify int // hasher.Verify calls
	}{
		{"ok", "alice@example.com", "long enough password", true, 1},
		{"case and spaces", " ALICE@example.com ", "long enough password", true, 1},
		{"wrong password", "alice@example.com", "wrong password!!", false, 1},
		{"unknown login still hashes", "bob@example.com", "long enough password", false, 1},
		{"empty password", "alice@example.com", "", false, 0},
		{"oversized password", "alice@example.com", string(make([]byte, 2000)), false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h.verifies = 0
			got, err := p.Authenticate(ctx, map[string]string{"username": tt.user, "password": tt.pw})
			if tt.ok != (err == nil) {
				t.Fatalf("err = %v, want ok=%v", err, tt.ok)
			}
			if !tt.ok && !errors.Is(err, provider.ErrInvalidCredentials) {
				t.Fatalf("err %v does not wrap ErrInvalidCredentials", err)
			}
			if tt.ok && got.ProviderID != "alice@example.com" {
				t.Fatalf("identity = %+v", got)
			}
			if h.verifies != tt.wantVerify {
				t.Fatalf("Verify called %d times, want %d", h.verifies, tt.wantVerify)
			}
		})
	}
}

func TestProviderMigratesBcrypt(t *testing.T) {
	ctx := context.Background()
	bc, _ := bcrypt.GenerateFromPassword([]byte("legacy password"), bcrypt.MinCost)
	store := creds{"old@example.com": string(bc)}
	p, _ := NewProvider(store, newHasher(t, fast), Policy{})

	if _, err := p.Authenticate(ctx, map[string]string{"username": "old@example.com", "password": "legacy password"}); err != nil {
		t.Fatal(err)
	}
	if !isArgon2id(store["old@example.com"]) {
		t.Fatalf("hash not migrated: %q", store["old@example.com"])
	}
	if _, err := p.Authenticate(ctx, map[string]string{"username": "old@example.com", "password": "legacy password"}); err != nil {
		t.Fatalf("login after migration: %v", err)
	}
}

func isArgon2id(s string) bool { _, _, _, err := decode(s); return err == nil }
