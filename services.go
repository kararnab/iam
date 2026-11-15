package iam

// Services is the default implementation seen through each of its
// interfaces, so an application gets Recovery, MFA, Passwords and
// InviteAdmin without type assertions. It embeds Service, so a *Services
// can be used wherever the Service methods are called; pass its Service
// field where an iam.Service value is needed (httpauth.Config.Service).
//
// Every field is set. A feature that is not configured answers its "not
// configured" error (ErrRecoveryNotConfigured, ErrMFANotConfigured,
// ErrPasswordsNotConfigured, ErrInvitesNotManaged); check the Config, not
// the fields, to decide at start-up whether a feature is on.
type Services struct {
	Service
	Recovery    Recovery
	MFA         MFA
	Passwords   Passwords
	InviteAdmin InviteAdmin
}

// NewServices validates cfg and returns the default implementation with
// every interface typed. It is New for applications that use more than
// Service:
//
//	svcs, err := iam.NewServices(cfg)
//	...
//	tok, err := svcs.Recovery.StartPasswordReset(ctx, req)
func NewServices(cfg Config) (*Services, error) {
	svc, err := New(cfg)
	if err != nil {
		return nil, err
	}
	s := svc.(*service)
	return &Services{Service: s, Recovery: s, MFA: s, Passwords: s, InviteAdmin: s}, nil
}
