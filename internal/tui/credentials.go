package tui

import (
	"context"
	"errors"
	"strings"

	"github.com/xjoker/ssh-mcp/internal/auth"
	"github.com/xjoker/ssh-mcp/internal/config"
)

type osCredentialStore struct{}

func (osCredentialStore) Status(ctx context.Context, ref config.CredRef) (credentialState, error) {
	secret, err := auth.Resolve(ctx, ref, false)
	if err != nil {
		if errors.Is(err, auth.ErrKeyNotFound) {
			return credentialMissing, nil
		}
		return credentialUnavailable, err
	}
	if secret == nil {
		return credentialMissing, nil
	}
	secret.Close()
	return credentialStored, nil
}

func (osCredentialStore) Set(service, account string, secret []byte) error {
	return auth.SetKeychain(service, account, secret)
}

func (osCredentialStore) Delete(service, account string) error {
	return auth.DeleteKeychain(service, account)
}

type credentialResultMsg struct {
	name       string
	generation uint64
	state      credentialState
	err        error
	ref        config.CredRef
}

func sanitizeCredentialError(err error, ref config.CredRef) string {
	if err == nil {
		return ""
	}
	detail := err.Error()
	for _, sensitive := range []string{ref.Raw, ref.Value} {
		if sensitive != "" {
			detail = strings.ReplaceAll(detail, sensitive, "[redacted]")
		}
	}
	return terminalText(detail)
}
