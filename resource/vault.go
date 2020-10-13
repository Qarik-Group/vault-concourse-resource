package resource

import (
	svault "github.com/starkandwayne/safe/vault"
	"github.com/starkandwayne/vault-concourse-resource/vault"
)

func GetRealVaultClient(vaultURL string) (vault.Client, error) {
	return svault.NewVault(svault.VaultConfig{
		URL:        vaultURL,
		SkipVerify: true,
		Token:      "noTokenYet",
	})
}
