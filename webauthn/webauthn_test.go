package webauthn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/kararnab/iam/v2"
	"github.com/kararnab/iam/v2/memstore"
	"github.com/kararnab/iam/v2/policy"
	"github.com/kararnab/iam/v2/provider"
	"github.com/kararnab/iam/v2/session"
)

const (
	rpID   = "app.example"
	origin = "https://app.example"
)

var (
	ctx = context.Background()
	b64 = base64.RawURLEncoding
)

// authenticator is a software passkey: a P-256 key, "none" attestation,
// user verification and backup flags set.
type authenticator struct {
	t         *testing.T
	key       *ecdsa.PrivateKey
	id        []byte
	signCount uint32
	noUV      bool
}

func newAuthenticator(t *testing.T) *authenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &authenticator{t: t, key: key, id: id}
}

func (a *authenticator) flags(attested bool) byte {
	f := byte(0x01 | 0x08 | 0x10) // UP, BE, BS
	if !a.noUV {
		f |= 0x04
	}
	if attested {
		f |= 0x40
	}
	return f
}

func (a *authenticator) authData(rp string, attested bool) []byte {
	h := sha256.Sum256([]byte(rp))
	out := append([]byte{}, h[:]...)
	out = append(out, a.flags(attested))
	out = binary.BigEndian.AppendUint32(out, a.signCount)
	if attested {
		out = append(out, make([]byte, 16)...) // AAGUID
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.id)))
		out = append(out, a.id...)
		x, y := make([]byte, 32), make([]byte, 32)
		a.key.X.FillBytes(x)
		a.key.Y.FillBytes(y)
		cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
		if err != nil {
			a.t.Fatal(err)
		}
		out = append(out, cose...)
	}
	return out
}

func challengeOf(t *testing.T, options []byte) string {
	t.Helper()
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &o); err != nil || o.PublicKey.Challenge == "" {
		t.Fatalf("options = %s, %v", options, err)
	}
	return o.PublicKey.Challenge
}

func clientData(typ, challenge, org string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": org, "crossOrigin": false})
	return b
}

// register answers navigator.credentials.create().
func (a *authenticator) register(options []byte, org string) []byte {
	a.t.Helper()
	cd := clientData("webauthn.create", challengeOf(a.t, options), org)
	att, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(rpID, true)})
	if err != nil {
		a.t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.id), "rawId": b64.EncodeToString(a.id), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON": b64.EncodeToString(cd), "attestationObject": b64.EncodeToString(att),
			"transports": []string{"internal", "hybrid"},
		},
	})
	return body
}

// assert answers navigator.credentials.get().
func (a *authenticator) assert(options []byte, org, userHandle string) []byte {
	a.t.Helper()
	a.signCount++
	cd := clientData("webauthn.get", challengeOf(a.t, options), org)
	ad := a.authData(rpID, false)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		a.t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.id), "rawId": b64.EncodeToString(a.id), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON": b64.EncodeToString(cd), "authenticatorData": b64.EncodeToString(ad),
			"signature": b64.EncodeToString(sig), "userHandle": b64.EncodeToString([]byte(userHandle)),
		},
	})
	return body
}

type fixture struct {
	pk    *Provider
	svc   iam.Service
	users *memstore.Users
	creds *memstore.Passkeys
	now   time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{users: memstore.NewUsers(), creds: memstore.NewPasskeys(), now: time.Now()}
	f.users.PutSubject(iam.Subject{ID: "s-ana", Roles: []string{"member"}})
	f.users.PutSubject(iam.Subject{ID: "s-bob", Roles: []string{"member"}})
	pk, err := New(Config{
		RPID: rpID, RPDisplayName: "Example", RPOrigins: []string{origin},
		Credentials: f.creds, Identities: f.users, Key: []byte("a WebAuthn state key of 32 bytes"),
		Now: func() time.Time { return f.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	rbac, _ := policy.NewRBAC(map[string][]policy.Permission{"member": {policy.P("read", "x")}})
	svc, err := iam.New(iam.Config{
		Providers: []provider.AuthProvider{pk},
		Users:     f.users,
		Sessions:  memstore.NewSessions(),
		Policy:    rbac,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.pk, f.svc = pk, svc
	return f
}

func (f *fixture) enroll(t *testing.T, a *authenticator, subject string) {
	t.Helper()
	opts, st, err := f.pk.BeginRegistration(ctx, User{SubjectID: subject, Name: subject + "@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.pk.FinishRegistration(ctx, subject, st, a.register(opts, origin), "laptop")
	if err != nil {
		t.Fatalf("FinishRegistration = %v", err)
	}
	if c.SubjectID != subject || !c.UserVerified || !c.BackupEligible || c.Name != "laptop" {
		t.Fatalf("credential = %+v", c)
	}
}

func (f *fixture) login(t *testing.T, a *authenticator, userHandle string) (*iam.LoginResult, error) {
	t.Helper()
	opts, st, err := f.pk.BeginLogin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return f.svc.Login(ctx, iam.AuthRequest{
		Provider: f.pk.Name(),
		Params:   map[string]string{"state": st, "response": string(a.assert(opts, origin, userHandle))},
		Mode:     session.ModeCookie,
	})
}

func TestRegisterAndLogin(t *testing.T) {
	f := newFixture(t)
	a := newAuthenticator(t)
	f.enroll(t, a, "s-ana")

	res, err := f.login(t, a, "s-ana")
	if err != nil || res.Subject.ID != "s-ana" || res.Session.Provider != "passkey" {
		t.Fatalf("Login = %+v, %v", res, err)
	}
	stored, _ := f.creds.Get(ctx, a.id)
	if stored.SignCount != a.signCount || stored.LastUsedAt.IsZero() {
		t.Fatalf("not touched: %+v", stored)
	}
	list, _ := f.pk.Credentials(ctx, "s-ana")
	if len(list) != 1 {
		t.Fatalf("credentials = %v", list)
	}

	// The same authenticator cannot be registered twice for the subject.
	opts, _, err := f.pk.BeginRegistration(ctx, User{SubjectID: "s-ana", Name: "ana"})
	if err != nil {
		t.Fatal(err)
	}
	var o struct {
		PublicKey struct {
			Exclude []struct {
				ID string `json:"id"`
			} `json:"excludeCredentials"`
		} `json:"publicKey"`
	}
	_ = json.Unmarshal(opts, &o)
	if len(o.PublicKey.Exclude) != 1 || o.PublicKey.Exclude[0].ID != b64.EncodeToString(a.id) {
		t.Fatalf("excludeCredentials = %+v", o.PublicKey.Exclude)
	}

	// Removing it unlinks the identity and stops logins.
	if err := f.pk.RemoveCredential(ctx, "s-ana", a.id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.login(t, a, "s-ana"); !errors.Is(err, iam.ErrInvalidCredentials) {
		t.Fatalf("login after removal = %v", err)
	}
	if _, err := f.users.ResolveIdentity(ctx, "passkey", ProviderID(a.id)); !errors.Is(err, iam.ErrNotFound) {
		t.Fatalf("identity still linked: %v", err)
	}
}

func TestLoginRejects(t *testing.T) {
	f := newFixture(t)
	a := newAuthenticator(t)
	f.enroll(t, a, "s-ana")
	try := func(params map[string]string) error {
		_, err := f.svc.Login(ctx, iam.AuthRequest{Provider: "passkey", Params: params})
		return err
	}
	begin := func() ([]byte, string) {
		opts, st, err := f.pk.BeginLogin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return opts, st
	}

	t.Run("wrong origin", func(t *testing.T) {
		opts, st := begin()
		if err := try(map[string]string{"state": st, "response": string(a.assert(opts, "https://evil.example", "s-ana"))}); !errors.Is(err, iam.ErrInvalidCredentials) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("response for another challenge", func(t *testing.T) {
		opts, _ := begin()
		_, st := begin()
		if err := try(map[string]string{"state": st, "response": string(a.assert(opts, origin, "s-ana"))}); !errors.Is(err, iam.ErrInvalidCredentials) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("user handle of another subject", func(t *testing.T) {
		opts, st := begin()
		if err := try(map[string]string{"state": st, "response": string(a.assert(opts, origin, "s-bob"))}); !errors.Is(err, iam.ErrInvalidCredentials) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("signed by another key", func(t *testing.T) {
		opts, st := begin()
		forger := newAuthenticator(t)
		forger.id = a.id
		if err := try(map[string]string{"state": st, "response": string(forger.assert(opts, origin, "s-ana"))}); !errors.Is(err, iam.ErrInvalidCredentials) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("unknown credential", func(t *testing.T) {
		opts, st := begin()
		if err := try(map[string]string{"state": st, "response": string(newAuthenticator(t).assert(opts, origin, "s-ana"))}); !errors.Is(err, iam.ErrInvalidCredentials) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("without user verification", func(t *testing.T) {
		opts, st := begin()
		a.noUV = true
		defer func() { a.noUV = false }()
		if err := try(map[string]string{"state": st, "response": string(a.assert(opts, origin, "s-ana"))}); !errors.Is(err, iam.ErrInvalidCredentials) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("cloned authenticator", func(t *testing.T) {
		if _, err := f.login(t, a, "s-ana"); err != nil { // counter now > 0 and stored
			t.Fatal(err)
		}
		a.signCount -= 2 // the clone is behind
		opts, st := begin()
		if err := try(map[string]string{"state": st, "response": string(a.assert(opts, origin, "s-ana"))}); !errors.Is(err, iam.ErrInvalidCredentials) {
			t.Fatalf("err = %v", err)
		}
		a.signCount += 10
	})
	t.Run("registration state used for login", func(t *testing.T) {
		opts, st, _ := f.pk.BeginRegistration(ctx, User{SubjectID: "s-ana", Name: "ana"})
		if err := try(map[string]string{"state": st, "response": string(a.assert(opts, origin, "s-ana"))}); !errors.Is(err, iam.ErrInvalidCredentials) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("expired state", func(t *testing.T) {
		opts, st := begin()
		f.now = f.now.Add(6 * time.Minute)
		defer func() { f.now = f.now.Add(-6 * time.Minute) }()
		if err := try(map[string]string{"state": st, "response": string(a.assert(opts, origin, "s-ana"))}); !errors.Is(err, iam.ErrInvalidCredentials) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("garbage", func(t *testing.T) {
		_, st := begin()
		for _, p := range []map[string]string{{}, {"state": "x", "response": "{}"}, {"state": st, "response": "not json"}} {
			if err := try(p); !errors.Is(err, iam.ErrInvalidCredentials) {
				t.Fatalf("%v: %v", p, err)
			}
		}
	})
}

func TestRegistrationRejects(t *testing.T) {
	f := newFixture(t)
	a := newAuthenticator(t)
	opts, st, err := f.pk.BeginRegistration(ctx, User{SubjectID: "s-ana", Name: "ana"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pk.FinishRegistration(ctx, "s-bob", st, a.register(opts, origin), ""); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("state of another subject = %v", err)
	}
	if _, err := f.pk.FinishRegistration(ctx, "s-ana", st, a.register(opts, "https://evil.example"), ""); !errors.Is(err, ErrRegistration) {
		t.Fatalf("wrong origin = %v", err)
	}
	loginOpts, loginState, _ := f.pk.BeginLogin(ctx)
	if _, err := f.pk.FinishRegistration(ctx, "s-ana", loginState, a.register(loginOpts, origin), ""); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("login state used to register = %v", err)
	}
	if _, err := f.pk.FinishRegistration(ctx, "s-ana", st, []byte("{}"), ""); !errors.Is(err, ErrRegistration) {
		t.Fatalf("garbage = %v", err)
	}
	if list, _ := f.creds.ListBySubject(ctx, "s-ana"); len(list) != 0 {
		t.Fatalf("a failed registration stored %v", list)
	}

	// A credential ID that is already registered (to anyone) is refused,
	// and nothing is linked.
	f.enroll(t, a, "s-ana")
	opts, st, _ = f.pk.BeginRegistration(ctx, User{SubjectID: "s-bob", Name: "bob"})
	if _, err := f.pk.FinishRegistration(ctx, "s-bob", st, a.register(opts, origin), ""); err == nil {
		t.Fatal("the same credential was registered for a second subject")
	}
	if _, err := f.users.ResolveIdentity(ctx, "passkey", ProviderID(a.id)); err != nil {
		t.Fatal(err)
	}
}

func TestNewValidates(t *testing.T) {
	users := memstore.NewUsers()
	good := Config{
		RPID: rpID, RPDisplayName: "x", RPOrigins: []string{origin},
		Credentials: memstore.NewPasskeys(), Identities: users, Key: make([]byte, 32),
	}
	cases := map[string]func(*Config){
		"no store":     func(c *Config) { c.Credentials = nil },
		"no links":     func(c *Config) { c.Identities = nil },
		"no RPID":      func(c *Config) { c.RPID = "" },
		"no origins":   func(c *Config) { c.RPOrigins = nil },
		"short key":    func(c *Config) { c.Key = []byte("short") },
		"long timeout": func(c *Config) { c.Timeout = time.Hour },
	}
	for name, mutate := range cases {
		cfg := good
		mutate(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if p, err := New(good); err != nil || p.Name() != "passkey" {
		t.Fatalf("good = %v, %v", p, err)
	}
}
