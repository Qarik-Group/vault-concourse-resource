package vault

import (
	"github.com/cloudfoundry-community/vaultkv"
)

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 . Client

type Client interface {
	AuthApprole(roleID, secretID string) (ret *vaultkv.AuthOutput, err error)

	ListMounts() (map[string]vaultkv.Mount, error)
	IsKVv2Mount(path string) (mountPath string, isV2 bool, err error)

	List(path string) ([]string, error)
	Get(path string, output interface{}) error
	Set(path string, values map[string]string) error

	V2List(mount, subpath string) ([]string, error)
	V2Get(mount, subpath string, output interface{}, opts *vaultkv.V2GetOpts) (meta vaultkv.V2Version, err error)
	V2Set(mount, subpath string, values interface{}, opts *vaultkv.V2SetOpts) (meta vaultkv.V2Version, err error)
}
