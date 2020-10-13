package vault

import (
	"github.com/cloudfoundry-community/vaultkv"
	"github.com/starkandwayne/safe/vault"
)

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 . Client

type Client interface {
	Write(path string, s *vault.Secret) error
	ConstructSecrets(path string, opts vault.TreeOpts) (s vault.Secrets, err error)
	Client() *vaultkv.KV
}
