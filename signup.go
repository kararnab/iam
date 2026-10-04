package iam

import (
	"context"
	"crypto/rand"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/kararnab/iam/v2/audit"
	"github.com/kararnab/iam/v2/invite"
	"github.com/kararnab/iam/v2/metrics"
	"github.com/kararnab/iam/v2/provider"
	"github.com/kararnab/iam/v2/session"
)

// SignUpRequest creates a new subject and starts a session.
//
// With a provider that implements provider.Registrar (password), new
// credentials are registered from Params. With other providers (OIDC), the
// identity is authenticated and must not be linked yet.
type SignUpRequest struct {
	InviteToken string // required when the sign-up policy is InviteOnly
	Provider    string
	Params      map[string]string
	Mode        session.Mode
	Client      ClientInfo
}

// InviteRequest describes an invite to create.
//
// IAM does not decide who may invite whom: the application must authorize
// the inviter (including which Roles they may grant) before calling.
type InviteRequest struct {
	CreatedBy string        // inviter's subject ID, for audit
	Email     string        // optional; binds the invite to this email
	Roles     []string      // granted to the new subject
	TTL       time.Duration // zero means Config.Signup.InviteTTL
}

// IssuedInvite is returned once by CreateInvite. Token is the only copy of
// the secret; deliver it to the invitee (IAM sends no email).
type IssuedInvite struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *service) SignUp(ctx context.Context, req SignUpRequest) (res *LoginResult, err error) {
	fail := func(reason string, err error) (*LoginResult, error) {
		s.cfg.Metrics.Inc(metrics.SignupFailure)
		s.audit(ctx, audit.Event{
			Type:     audit.EventSignup,
			Provider: req.Provider,
			ClientIP: req.Client.IP,
			Message:  "sign-up failed",
			Attrs:    map[string]string{"reason": reason},
		})
		return nil, err
	}

	policy := s.cfg.Signup.Policy
	if policy == invite.Closed {
		return fail("closed", ErrSignupClosed)
	}

	mode := req.Mode
	if mode == "" {
		mode = s.cfg.AllowedModes[0]
	}
	if !s.modeAllowed(mode) {
		return fail("mode_not_allowed", ErrModeNotAllowed)
	}

	// Check the invite before doing any work, so a bad invite registers nothing.
	var inviteHash []byte
	var inv *invite.Invite
	if policy == invite.InviteOnly {
		if inviteHash, err = session.HashSecret(req.InviteToken); err != nil {
			return fail("invalid_invite", ErrInvalidInvite)
		}
		inv, err = s.cfg.Signup.Invites.GetByTokenHash(ctx, inviteHash)
		if err != nil || !inv.Usable(s.cfg.Now()) {
			return fail("invalid_invite", ErrInvalidInvite)
		}
	}

	prov, ok := s.providers[req.Provider]
	if !ok {
		return fail("unknown_provider", ErrUnknownProvider)
	}

	// Obtain the identity, registering credentials if the provider can.
	var identity *provider.Identity
	registrar, registers := prov.(provider.Registrar)
	if registers {
		identity, err = registrar.Register(ctx, req.Params)
		if errors.Is(err, ErrConflict) {
			return fail("already_registered", ErrAlreadyRegistered)
		}
	} else {
		identity, err = s.authenticate(ctx, AuthRequest{Provider: req.Provider, Params: req.Params, Client: req.Client})
	}
	if err != nil {
		return fail("invalid_identity", err)
	}

	// From here on, undo the registration if sign-up does not complete.
	defer func() {
		if err != nil && registers {
			_ = registrar.Unregister(ctx, identity.ProviderID)
		}
	}()

	switch _, rerr := s.cfg.Users.ResolveIdentity(ctx, identity.Provider, identity.ProviderID); {
	case rerr == nil:
		return fail("already_registered", ErrAlreadyRegistered)
	case !errors.Is(rerr, ErrNotFound):
		return fail("store_error", rerr)
	}

	grant := SignupGrant{Roles: slices.Clone(s.cfg.Signup.DefaultRoles)}
	if inv != nil {
		if inv.Email != "" && !strings.EqualFold(inv.Email, identity.Email) {
			return fail("invite_email_mismatch", ErrInvalidInvite)
		}
		// Consume atomically before creating the subject: of two sign-ups
		// racing on one invite, only one gets past this point.
		used, cerr := s.cfg.Signup.Invites.Consume(ctx, inviteHash, identity.Provider+":"+identity.ProviderID, s.cfg.Now())
		if cerr != nil {
			return fail("invalid_invite", ErrInvalidInvite)
		}
		grant = SignupGrant{Roles: slices.Clone(used.Roles), InviteID: used.ID}
		s.audit(ctx, audit.Event{
			Type:     audit.EventInviteConsumed,
			Provider: identity.Provider,
			ClientIP: req.Client.IP,
			Message:  "invite consumed",
			Attrs:    map[string]string{"invite_id": used.ID, "invited_by": used.CreatedBy},
		})
	}

	subjectID, err := s.cfg.Users.CreateSubject(ctx, *identity, grant)
	if err != nil {
		return fail("store_error", err)
	}
	if err = s.cfg.Users.LinkIdentity(ctx, subjectID, *identity); err != nil {
		return fail("store_error", err)
	}
	subject, err := s.loadActiveSubject(ctx, subjectID)
	if err != nil {
		return fail(reasonFor(err), err)
	}
	res, err = s.startSession(ctx, subject, mode, identity.Provider, req.Client, "")
	if err != nil {
		return fail("session_error", err)
	}

	s.cfg.Metrics.Inc(metrics.Signup)
	s.audit(ctx, audit.Event{
		Type:      audit.EventSignup,
		SubjectID: subject.ID,
		SessionID: res.Session.ID,
		Provider:  identity.Provider,
		ClientIP:  req.Client.IP,
		Message:   "signed up",
		Attrs:     map[string]string{"invite_id": grant.InviteID},
	})
	return res, nil
}

func (s *service) CreateInvite(ctx context.Context, req InviteRequest) (*IssuedInvite, error) {
	if s.cfg.Signup.Invites == nil {
		return nil, errors.New("iam: invites are not configured")
	}
	ttl := req.TTL
	if ttl == 0 {
		ttl = s.cfg.Signup.InviteTTL
	}
	if ttl < 0 || ttl > 90*24*time.Hour {
		return nil, errors.New("iam: invite TTL must be between 0 and 90 days")
	}

	now := s.cfg.Now()
	tok, hash := session.NewSecret()
	inv := &invite.Invite{
		ID:        rand.Text(),
		TokenHash: hash,
		Email:     strings.ToLower(strings.TrimSpace(req.Email)),
		Roles:     slices.Clone(req.Roles),
		CreatedBy: req.CreatedBy,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
	if err := s.cfg.Signup.Invites.Create(ctx, inv); err != nil {
		return nil, err
	}

	s.audit(ctx, audit.Event{
		Type:      audit.EventInviteCreated,
		SubjectID: req.CreatedBy,
		Message:   "invite created",
		Attrs: map[string]string{
			"invite_id":   inv.ID,
			"roles":       strings.Join(inv.Roles, ","),
			"email_bound": boolString(inv.Email != ""),
		},
	})
	return &IssuedInvite{ID: inv.ID, Token: tok, ExpiresAt: inv.ExpiresAt}, nil
}

func (s *service) RevokeInvite(ctx context.Context, inviteID string) error {
	if s.cfg.Signup.Invites == nil {
		return errors.New("iam: invites are not configured")
	}
	return s.cfg.Signup.Invites.Delete(ctx, inviteID)
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
