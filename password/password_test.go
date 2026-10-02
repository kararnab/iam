package password

import (
	"context"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// fast parameters keep the tests quick; production uses DefaultParams.
var fast = Params{Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}

func newHasher(t *testing.T, p Params) *Argon2id {
	t.Helper()
	h, err := NewArgon2id(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestHashVerify(t *testing.T) {
	ctx := context.Background()
	h := newHasher(t, fast)
	enc, err := h.Hash(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("encoded = %q", enc)
	}
	again, _ := h.Hash(ctx, "correct horse battery staple")
	if again == enc {
		t.Fatal("two hashes of the same password are equal (salt not random)")
	}

	bc, _ := bcrypt.GenerateFromPassword([]byte("legacy-password"), bcrypt.MinCost)

	tests := []struct {
		name    string
		pw      string
		enc     string
		want    bool
		wantErr bool
	}{
		{"argon2id match", "correct horse battery staple", enc, true, false},
		{"argon2id mismatch", "wrong", enc, false, false},
		{"argon2id empty password", "", enc, false, false},
		{"bcrypt match", "legacy-password", string(bc), true, false},
		{"bcrypt mismatch", "nope", string(bc), false, false},
		{"bcrypt over 72 bytes", strings.Repeat("a", 100), string(bc), false, false},
		{"malformed", "x", "$argon2id$garbage", false, true},
		{"unknown scheme", "x", "$scrypt$whatever", false, true},
		{"empty", "x", "", false, true},
		{"bcrypt malformed", "x", "$2b$xx", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := h.Verify(ctx, tt.pw, tt.enc)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Fatalf("Verify = %v, %v; want %v, err=%v", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestNeedsRehash(t *testing.T) {
	ctx := context.Background()
	h := newHasher(t, fast)
	enc, _ := h.Hash(ctx, "pw")
	stronger := fast
	stronger.Iterations = 2
	bc, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)

	tests := []struct {
		name   string
		hasher *Argon2id
		enc    string
		want   bool
	}{
		{"same params", h, enc, false},
		{"params raised", newHasher(t, stronger), enc, true},
		{"bcrypt", h, string(bc), true},
		{"garbage", h, "garbage", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.hasher.NeedsRehash(tt.enc); got != tt.want {
				t.Fatalf("NeedsRehash = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecodeRejects(t *testing.T) {
	salt := "c2FsdHNhbHRzYWx0c2FsdA"          // 16 bytes
	key := "a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5" // 24 bytes
	tests := []string{
		"$argon2i$v=19$m=64,t=1,p=1$" + salt + "$" + key,
		"$argon2id$v=16$m=64,t=1,p=1$" + salt + "$" + key,
		"$argon2id$v=19$m=64,t=1$" + salt + "$" + key,
		"$argon2id$v=19$m=064,t=1,p=1$" + salt + "$" + key,
		"$argon2id$v=19$m=-1,t=1,p=1$" + salt + "$" + key,
		"$argon2id$v=19$m=99999999999,t=1,p=1$" + salt + "$" + key,
		"$argon2id$v=19$m=64,t=0,p=1$" + salt + "$" + key,
		"$argon2id$v=19$m=64,t=1,p=0$" + salt + "$" + key,
		"$argon2id$v=19$m=4,t=1,p=1$" + salt + "$" + key,
		"$argon2id$v=19$m=64,t=1,p=1$" + salt + "==$" + key,
		"$argon2id$v=19$m=64,t=1,p=1$" + salt + "$" + key + "$extra",
		"$argon2id$v=19$m=64,t=1,p=1$$" + key,
		"$argon2id$v=19$m=2000000,t=1,p=1$" + salt + "$" + key,
	}
	for _, enc := range tests {
		t.Run(enc, func(t *testing.T) {
			if _, _, _, err := decode(enc); !errors.Is(err, ErrMalformedHash) {
				t.Fatalf("decode accepted %q", enc)
			}
		})
	}
	if _, _, _, err := decode("$argon2id$v=19$m=64,t=1,p=1$" + salt + "$" + key); err != nil {
		t.Fatalf("valid hash rejected: %v", err)
	}
}

func TestNewArgon2idValidatesParams(t *testing.T) {
	bad := []Params{
		{Memory: 0, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32},
		{Memory: 64, Iterations: 0, Parallelism: 1, SaltLength: 16, KeyLength: 32},
		{Memory: 64, Iterations: 1, Parallelism: 0, SaltLength: 16, KeyLength: 32},
		{Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 8, KeyLength: 32},
		{Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 8},
		{Memory: maxMemory + 1, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32},
	}
	for _, p := range bad {
		if _, err := NewArgon2id(p, 1); err == nil {
			t.Errorf("params %+v accepted", p)
		}
	}
	if _, err := NewArgon2id(DefaultParams, 1); err != nil {
		t.Fatalf("DefaultParams rejected: %v", err)
	}
}

func TestConcurrencyLimitHonoursContext(t *testing.T) {
	h, _ := NewArgon2id(fast, 1)
	h.sem <- struct{}{} // occupy the only slot
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.Hash(ctx, "pw"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Hash err = %v, want context.Canceled", err)
	}
}

func TestPolicy(t *testing.T) {
	tests := []struct {
		pw   string
		want error
	}{
		{"short", ErrTooShort},
		{"exactly12chr", nil},
		{"ääääääääääää", nil}, // 12 characters, 24 bytes
		{strings.Repeat("a", 1025), ErrTooLong},
		{strings.Repeat("a", 1024), nil},
	}
	for _, tt := range tests {
		if err := DefaultPolicy.Check(tt.pw); !errors.Is(err, tt.want) {
			t.Errorf("Check(%q...) = %v, want %v", tt.pw[:min(len(tt.pw), 12)], err, tt.want)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add("$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5")
	f.Add("$argon2id$v=19$m=19456,t=2,p=1$$")
	f.Add("$2b$10$abcdefghijklmnopqrstuv")
	f.Add("")
	f.Fuzz(func(t *testing.T, enc string) {
		p, salt, key, err := decode(enc)
		if err != nil {
			return
		}
		// Anything accepted must be within the safety limits and re-encode identically.
		if p.Memory > maxMemory || p.Iterations > maxIterations || p.Iterations == 0 || p.Parallelism == 0 {
			t.Fatalf("params out of bounds: %+v", p)
		}
		if encode(p, salt, key) != enc {
			t.Fatalf("non-canonical encoding accepted: %q", enc)
		}
	})
}
