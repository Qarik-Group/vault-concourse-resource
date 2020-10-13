package resource

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"os"

	"github.com/cloudfoundry-community/vaultkv"
	"github.com/starkandwayne/vault-concourse-resource/vault"
)

func GetRealVaultClient(vaultURL string) (vault.Client, error) {
	u, err := url.Parse(vaultURL)
	if err != nil {
		return nil, err
	}
	return &vaultkv.Client{
		VaultURL: u,
		Client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
		Trace: os.Stdout,
	}, nil
}

// func GetFakeVaultClient(s Source) (vault.Client, error) {

// }
