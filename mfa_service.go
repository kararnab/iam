package iam

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kararnab/iam/v2/audit"
	"github.com/kararnab/iam/v2/metrics"
	"github.com/kararnab/iam/v2/mfa"
	"github.com/kararnab/iam/v2/session"
)

var (
	// ErrMFARequired is wrapped by *MFARequiredError.
	ErrMFARequired = errors.New("iam: a second factor is required")

	// ErrMFANotConfigured is returned by MFA methods when Config.MFA.Store
	// is not set.
	ErrMFANotConfigured = errors.New("iam: multi-factor authentication is not configured")

	// ErrInvalidMFACode is returned for a wrong, reused or expired code, a
	// used recovery code, or an invalid or expired challenge.
	ErrInvalidMFACode = errors.New("iam: invalid authentication code")

	// ErrMFAAlreadyEnrolled is returned by BeginTOTPEnrollment when the
	// subject already has a confirmed factor. Disable it first.
	ErrMFAAlreadyEnrolled = errors.New("iam: a second factor is already enrolled")

	// ErrMFANotEnrolled is returned when the subject has no confirmed factor
	// (or, for ConfirmTOTPEnrollment, no pending one).
	ErrMFANotEnrolled = errors.New("iam: no second factor is enrolled")
)

// MFARequiredError is returned by Login when the first factor was correct
// and the subject has TOTP enrolled. No session exists yet: send Challenge
// to the client, ask for a code, and call MFA.CompleteMFA. It wraps
// ErrMFARequired, so code unaware of MFA treats it as a failed login.
type MFARequiredError struct {
	Challenge string    // opaque, sealed; give it back to CompleteMFA
	ExpiresAt time.Time // the code must be entered before this
}

func (e *MFARequiredError) Error() string { return "iam: a second factor is required" }

func (e *MFARequiredError) Unwrap() error { return ErrMFARequired }

// MFA is TOTP multi-factor authentication. The Service returned by New
// implements it:
//
//	m := svc.(iam.MFA)
//
// It is a separate interface so that adding it did not change Service.
// Every method that acts for a subject expects the application to have
// authorized the caller (normally: the subject itself, signed in, and
// recently re-authenticated for DisableTOTP and RegenerateRecoveryCodes).
type MFA interface {
	// BeginTOTPEnrollment creates a pending TOTP factor and returns its
	// secret, to show as a QR code (URI) or text (Secret). It replaces any
	// pending factor; a confirmed one gives ErrMFAAlreadyEnrolled.
	BeginTOTPEnrollment(ctx context.Context, subjectID, accountName string) (*TOTPEnrollment, error)

	// ConfirmTOTPEnrollment checks a first code from the app, turns the
	// factor on, and returns recovery codes to show the user once.
	ConfirmTOTPEnrollment(ctx context.Context, subjectID, code string) (recoveryCodes []string, err error)

	// DisableTOTP removes the subject's factor, pending or confirmed.
	DisableTOTP(ctx context.Context, subjectID string) error

	// TOTPEnabled reports whether the subject has a confirmed factor.
	TOTPEnabled(ctx context.Context, subjectID string) (bool, error)

	// CompleteMFA finishes a login that returned *MFARequiredError, with a
	// TOTP code or a recovery code, and starts the session. Wrong codes are
	// throttled per subject (*RateLimitError).
	CompleteMFA(ctx context.Context, req MFARequest) (*LoginResult, error)

	// VerifyMFA checks a code for a signed-in subject, as step-up
	// authentication before a sensitive action. It is throttled like
	// CompleteMFA.
	VerifyMFA(ctx context.Context, subjectID, code string, client ClientInfo) error

	// RegenerateRecoveryCodes replaces the subject's recovery codes.
	RegenerateRecoveryCodes(ctx context.Context, subjectID string) ([]string, error)
}

// TOTPEnrollment is returned by BeginTOTPEnrollment. Secret is shown to
// the user once; it has no JSON encoding on purpose.
type TOTPEnrollment struct {
	Secret string `json:"-"` // base32, for typing into an app
	URI    string `json:"-"` // otpauth://totp/..., for a QR code
}

// MFARequest completes a login with a second factor.
type MFARequest struct {
	Challenge string // from MFARequiredError
	Code      string // a TOTP code, or a recovery code
	Client    ClientInfo
}

var _ MFA = (*service)(nil)

// mfaChallenge is the sealed content of MFARequiredError.Challenge.
type mfaChallenge struct {
	SubjectID string       `json:"s"`
	Mode      session.Mode `json:"m"`
	Provider  string       `json:"p"`
	Expires   int64        `json:"e"`
}

// mfaAEAD returns AES-GCM keyed for one purpose from MFA.Key.
func (s *service) mfaAEAD(purpose string) (cipher.AEAD, error) {
	mac := hmac.New(sha256.New, s.cfg.MFA.Key)
	mac.Write([]byte("iam-mfa-" + purpose + "-v1"))
	block, err := aes.NewCipher(mac.Sum(nil))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *service) seal(purpose string, plain, aad []byte) ([]byte, error) {
	aead, err := s.mfaAEAD(purpose)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	return aead.Seal(nonce, nonce, plain, aad), nil
}

func (s *service) open(purpose string, sealed, aad []byte) ([]byte, error) {
	aead, err := s.mfaAEAD(purpose)
	if err != nil {
		return nil, err
	}
	n := aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("iam: sealed value too short")
	}
	return aead.Open(nil, sealed[:n], sealed[n:], aad)
}

// loginChallenge returns *MFARequiredError when the subject must give a
// second factor for this login, nil when not, or a store error. It fails
// closed: when the factor cannot be read, no session is started.
func (s *service) loginChallenge(ctx context.Context, subject *Subject, mode session.Mode, providerName string) error {
	if s.cfg.MFA.Store == nil || slices.Contains(s.cfg.MFA.ExemptProviders, providerName) {
		return nil
	}
	f, err := s.cfg.MFA.Store.GetTOTP(ctx, subject.ID)
	switch {
	case errors.Is(err, mfa.ErrNotFound):
		return nil
	case err != nil:
		return unavailableErr(err)
	case !f.Confirmed:
		return nil
	}
	expires := s.cfg.Now().Add(s.cfg.MFA.ChallengeTTL)
	plain, err := json.Marshal(mfaChallenge{SubjectID: subject.ID, Mode: mode, Provider: providerName, Expires: expires.Unix()})
	if err != nil {
		return err
	}
	sealed, err := s.seal("challenge", plain, nil)
	if err != nil {
		return err
	}
	return &MFARequiredError{Challenge: base64.RawURLEncoding.EncodeToString(sealed), ExpiresAt: expires}
}

func (s *service) openChallenge(challenge string) (*mfaChallenge, bool) {
	if len(challenge) > 1024 {
		return nil, false
	}
	sealed, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil {
		return nil, false
	}
	plain, err := s.open("challenge", sealed, nil)
	if err != nil {
		return nil, false
	}
	var c mfaChallenge
	if json.Unmarshal(plain, &c) != nil || c.SubjectID == "" || !s.cfg.Now().Before(time.Unix(c.Expires, 0)) {
		return nil, false
	}
	return &c, true
}

// ---------------------------------------------------------------------------
// Enrollment
// ---------------------------------------------------------------------------

func (s *service) BeginTOTPEnrollment(ctx context.Context, subjectID, accountName string) (*TOTPEnrollment, error) {
	store := s.cfg.MFA.Store
	if store == nil {
		return nil, ErrMFANotConfigured
	}
	if _, err := s.activeForMFA(ctx, subjectID); err != nil {
		return nil, err
	}
	switch f, err := store.GetTOTP(ctx, subjectID); {
	case err == nil && f.Confirmed:
		return nil, ErrMFAAlreadyEnrolled
	case err != nil && !errors.Is(err, mfa.ErrNotFound):
		return nil, unavailableErr(err)
	}

	secret := mfa.NewSecret()
	sealed, err := s.seal("secret", secret, []byte(subjectID))
	if err != nil {
		return nil, err
	}
	if err := store.PutTOTP(ctx, &mfa.TOTP{SubjectID: subjectID, Secret: sealed, CreatedAt: s.cfg.Now()}); err != nil {
		return nil, unavailableErr(err)
	}
	account := strings.TrimSpace(accountName)
	if account == "" {
		account = subjectID
	}
	return &TOTPEnrollment{Secret: mfa.EncodeSecret(secret), URI: mfa.URI(s.cfg.MFA.Issuer, account, secret)}, nil
}

func (s *service) ConfirmTOTPEnrollment(ctx context.Context, subjectID, code string) ([]string, error) {
	store := s.cfg.MFA.Store
	if store == nil {
		return nil, ErrMFANotConfigured
	}
	if _, err := s.activeForMFA(ctx, subjectID); err != nil {
		return nil, err
	}
	f, err := store.GetTOTP(ctx, subjectID)
	switch {
	case errors.Is(err, mfa.ErrNotFound) || (err == nil && f.Confirmed):
		return nil, ErrMFANotEnrolled
	case err != nil:
		return nil, unavailableErr(err)
	}
	if err := s.throttleMFA(ctx, subjectID, ClientInfo{}); err != nil {
		return nil, err
	}
	secret, err := s.open("secret", f.Secret, []byte(subjectID))
	if err != nil {
		return nil, fmt.Errorf("iam: open TOTP secret (was MFA.Key changed?): %w", err)
	}
	step, ok := mfa.Validate(secret, code, s.cfg.Now(), s.cfg.MFA.Skew)
	if !ok {
		s.failMFA(ctx, subjectID, ClientInfo{}, "invalid_code")
		return nil, ErrInvalidMFACode
	}
	codes, hashes := mfa.NewRecoveryCodes()
	f.Confirmed, f.LastStep, f.RecoveryCodes = true, step, hashes
	if err := store.PutTOTP(ctx, f); err != nil {
		return nil, unavailableErr(err)
	}
	s.resetMFAThrottle(ctx, subjectID)
	s.audit(ctx, audit.Event{Type: audit.EventMFAEnrolled, SubjectID: subjectID, Message: "TOTP enrolled", Attrs: map[string]string{"method": "totp"}})
	return codes, nil
}

func (s *service) DisableTOTP(ctx context.Context, subjectID string) error {
	store := s.cfg.MFA.Store
	if store == nil {
		return ErrMFANotConfigured
	}
	if err := store.DeleteTOTP(ctx, subjectID); err != nil {
		return unavailableErr(err)
	}
	s.audit(ctx, audit.Event{Type: audit.EventMFADisabled, SubjectID: subjectID, Message: "TOTP disabled", Attrs: map[string]string{"method": "totp"}})
	return nil
}

func (s *service) TOTPEnabled(ctx context.Context, subjectID string) (bool, error) {
	store := s.cfg.MFA.Store
	if store == nil {
		return false, ErrMFANotConfigured
	}
	f, err := store.GetTOTP(ctx, subjectID)
	switch {
	case errors.Is(err, mfa.ErrNotFound):
		return false, nil
	case err != nil:
		return false, unavailableErr(err)
	}
	return f.Confirmed, nil
}

func (s *service) RegenerateRecoveryCodes(ctx context.Context, subjectID string) ([]string, error) {
	store := s.cfg.MFA.Store
	if store == nil {
		return nil, ErrMFANotConfigured
	}
	f, err := store.GetTOTP(ctx, subjectID)
	switch {
	case errors.Is(err, mfa.ErrNotFound) || (err == nil && !f.Confirmed):
		return nil, ErrMFANotEnrolled
	case err != nil:
		return nil, unavailableErr(err)
	}
	codes, hashes := mfa.NewRecoveryCodes()
	f.RecoveryCodes = hashes
	if err := store.PutTOTP(ctx, f); err != nil {
		return nil, unavailableErr(err)
	}
	s.audit(ctx, audit.Event{Type: audit.EventRecoveryCodesIssued, SubjectID: subjectID, Message: "recovery codes regenerated"})
	return codes, nil
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

func (s *service) CompleteMFA(ctx context.Context, req MFARequest) (*LoginResult, error) {
	if s.cfg.MFA.Store == nil {
		return nil, ErrMFANotConfigured
	}
	c, ok := s.openChallenge(req.Challenge)
	if !ok {
		s.failMFA(ctx, "", req.Client, "invalid_challenge")
		return nil, ErrInvalidMFACode
	}
	subject, err := s.activeForMFA(ctx, c.SubjectID)
	if err != nil {
		s.failMFA(ctx, c.SubjectID, req.Client, reasonFor(err))
		if subjectGone(err) {
			return nil, ErrInvalidMFACode
		}
		return nil, err
	}
	method, err := s.checkCode(ctx, c.SubjectID, req.Code, req.Client)
	if err != nil {
		return nil, err
	}
	if !s.modeAllowed(c.Mode) {
		return nil, ErrModeNotAllowed
	}
	res, err := s.startSession(ctx, subject, c.Mode, c.Provider, req.Client, method)
	if err != nil {
		return nil, err
	}

	s.cfg.Metrics.Inc(metrics.LoginSuccess)
	s.audit(ctx, audit.Event{
		Type:      audit.EventLoginSuccess,
		SubjectID: subject.ID,
		SessionID: res.Session.ID,
		Provider:  c.Provider,
		ClientIP:  req.Client.IP,
		Message:   "login successful",
		Attrs:     map[string]string{"mode": string(c.Mode), "mfa": method},
	})
	return res, nil
}

func (s *service) VerifyMFA(ctx context.Context, subjectID, code string, client ClientInfo) error {
	if s.cfg.MFA.Store == nil {
		return ErrMFANotConfigured
	}
	if _, err := s.activeForMFA(ctx, subjectID); err != nil {
		return err
	}
	_, err := s.checkCode(ctx, subjectID, code, client)
	return err
}

// checkCode verifies a TOTP or recovery code for a subject with a
// confirmed factor, throttled, and returns the method ("totp" or
// "recovery_code").
func (s *service) checkCode(ctx context.Context, subjectID, code string, client ClientInfo) (string, error) {
	store := s.cfg.MFA.Store
	f, err := store.GetTOTP(ctx, subjectID)
	switch {
	case errors.Is(err, mfa.ErrNotFound) || (err == nil && !f.Confirmed):
		s.failMFA(ctx, subjectID, client, "not_enrolled")
		return "", ErrMFANotEnrolled
	case err != nil:
		return "", unavailableErr(err)
	}
	if err := s.throttleMFA(ctx, subjectID, client); err != nil {
		return "", err
	}

	code = strings.TrimSpace(code)
	if len(code) == mfa.Digits {
		secret, err := s.open("secret", f.Secret, []byte(subjectID))
		if err != nil {
			return "", fmt.Errorf("iam: open TOTP secret (was MFA.Key changed?): %w", err)
		}
		step, ok := mfa.Validate(secret, code, s.cfg.Now(), s.cfg.MFA.Skew)
		if ok {
			// Only a step later than the last one used counts, so an
			// observed code cannot be replayed.
			advanced, err := store.AdvanceTOTP(ctx, subjectID, step)
			if err != nil {
				return "", unavailableErr(err)
			}
			if advanced {
				s.succeedMFA(ctx, subjectID, client, "totp")
				return "totp", nil
			}
		}
		s.failMFA(ctx, subjectID, client, "invalid_code")
		return "", ErrInvalidMFACode
	}

	used, err := store.UseRecoveryCode(ctx, subjectID, mfa.HashRecoveryCode(code))
	if err != nil {
		return "", unavailableErr(err)
	}
	if !used {
		s.failMFA(ctx, subjectID, client, "invalid_recovery_code")
		return "", ErrInvalidMFACode
	}
	s.audit(ctx, audit.Event{
		Type: audit.EventRecoveryCodeUsed, SubjectID: subjectID, ClientIP: client.IP,
		Message: "recovery code used", Attrs: map[string]string{"remaining": strconv.Itoa(len(f.RecoveryCodes) - 1)},
	})
	s.succeedMFA(ctx, subjectID, client, "recovery_code")
	return "recovery_code", nil
}

// activeForMFA loads the subject and rejects disabled or missing ones.
func (s *service) activeForMFA(ctx context.Context, subjectID string) (*Subject, error) {
	subject, err := s.loadActiveSubject(ctx, subjectID)
	if err != nil && !subjectGone(err) {
		return nil, unavailableErr(err)
	}
	return subject, err
}

func (s *service) mfaLimitKey() (limitKey, bool) {
	if l := s.cfg.RateLimit.PerLogin; l != nil {
		return limitKey{limiter: l, scope: "mfa"}, true
	}
	return limitKey{}, false
}

// throttleMFA refuses a code check while the subject is throttled.
func (s *service) throttleMFA(ctx context.Context, subjectID string, client ClientInfo) error {
	k, ok := s.mfaLimitKey()
	if !ok {
		return nil
	}
	r, err := k.limiter.Check(ctx, "mfa:"+subjectID)
	if err != nil {
		return unavailableErr(err)
	}
	if !r.Allowed {
		s.cfg.Metrics.Inc(metrics.RateLimited)
		s.audit(ctx, audit.Event{
			Type: audit.EventRateLimited, SubjectID: subjectID, ClientIP: client.IP,
			Message: "attempt throttled", Attrs: map[string]string{"scope": "mfa"},
		})
		return &RateLimitError{RetryAfter: r.RetryAfter}
	}
	return nil
}

func (s *service) resetMFAThrottle(ctx context.Context, subjectID string) {
	if k, ok := s.mfaLimitKey(); ok {
		_ = k.limiter.Reset(ctx, "mfa:"+subjectID)
	}
}

func (s *service) failMFA(ctx context.Context, subjectID string, client ClientInfo, reason string) {
	if k, ok := s.mfaLimitKey(); ok && subjectID != "" && strings.HasPrefix(reason, "invalid_") {
		_, _ = k.limiter.Fail(ctx, "mfa:"+subjectID)
	}
	s.cfg.Metrics.Inc(metrics.MFAFailure)
	s.audit(ctx, audit.Event{
		Type: audit.EventMFAFailure, SubjectID: subjectID, ClientIP: client.IP,
		Message: "second factor rejected", Attrs: map[string]string{"reason": reason},
	})
}

func (s *service) succeedMFA(ctx context.Context, subjectID string, client ClientInfo, method string) {
	s.resetMFAThrottle(ctx, subjectID)
	s.cfg.Metrics.Inc(metrics.MFASuccess)
	s.audit(ctx, audit.Event{
		Type: audit.EventMFASuccess, SubjectID: subjectID, ClientIP: client.IP,
		Message: "second factor accepted", Attrs: map[string]string{"method": method},
	})
}
