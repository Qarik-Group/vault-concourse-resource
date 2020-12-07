// Package resource is an implementation of a Concourse resource.
package resource

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

	oc "github.com/cloudboss/ofcourse/ofcourse"
	sv "github.com/starkandwayne/safe/vault"
)

var (
	// ErrVersion means version map is malformed
	ErrVersion = errors.New(`key "count" not found in version map`)
	// ErrParam means parameters are malformed
	ErrParam = errors.New(`missing "version_path" parameter`)
)

// Resource implements the ofcourse.Resource interface.
type Resource struct {
	client *sv.Vault
}

func (r *Resource) configureClient(s Source) (err error) {
	r.client, err = sv.NewVault(sv.VaultConfig{
		URL:        s.URL,
		SkipVerify: true,
		Token:      s.Token,
	})
	if err != nil {
		return err
	}
	if s.RoleID != "" {
		_, err = r.client.Client().Client.AuthApprole(s.RoleID, s.SecretID)
		if err != nil {
			return err
		}
	}

	return nil
}

// Check implements the ofcourse.Resource Check method, corresponding to the /opt/resource/check command.
// This is called when Concourse does its resource checks, or when the `fly check-resource` command is run.
func (r *Resource) Check(source oc.Source, version oc.Version, env oc.Environment,
	logger *oc.Logger) ([]oc.Version, error) {

	s, err := parseSource(source)
	if err != nil {
		return nil, err
	}

	err = r.configureClient(s)
	if err != nil {
		return nil, err
	}

	secrets := sv.Secrets{}
	for _, p := range s.Paths {
		s, err := r.client.ConstructSecrets(p, sv.TreeOpts{
			FetchKeys: true,
		})
		if err != nil {
			return nil, err
		}
		secrets = secrets.Merge(s)
	}

	secrets.Sort()

	export := make(map[string]*sv.Secret)
	for _, s := range secrets {
		export[s.Path] = s.Versions[0].Data
	}

	raw, err := json.Marshal(&export)
	newVersion := newVersion(raw, s.URL)
	if version != nil {
		oldVersion, err := parseVersion(version)
		if err != nil {
			return nil, err
		}
		if oldVersion.equal(newVersion) {
			return []oc.Version{}, nil
		}
	}

	return []oc.Version{newVersion.toOCVersion()}, nil
}

// In implements the ofcourse.Resource In method, corresponding to the /opt/resource/in command.
// This is called when a Concourse job does `get` on the resource.
func (r *Resource) In(outputDirectory string, source oc.Source, params oc.Params, version oc.Version,
	env oc.Environment, logger *oc.Logger) (oc.Version, oc.Metadata, error) {

	s, err := parseSource(source)
	if err != nil {
		return nil, nil, err
	}

	err = r.configureClient(s)
	if err != nil {
		return nil, nil, err
	}

	secrets := sv.Secrets{}
	for _, p := range s.Paths {
		s, err := r.client.ConstructSecrets(p, sv.TreeOpts{
			FetchKeys: true,
		})
		if err != nil {
			return nil, nil, err
		}
		secrets = secrets.Merge(s)
	}

	secrets.Sort()

	for _, s := range secrets {
		filePath := filepath.Join(outputDirectory, s.Path)
		raw, err := s.Versions[0].Data.MarshalJSON()
		if err != nil {
			return nil, nil, err
		}

		err = os.MkdirAll(path.Dir(filePath), 0775)
		if err != nil {
			return nil, nil, err
		}

		err = ioutil.WriteFile(filePath, raw, 0644)
		if err != nil {
			return nil, nil, err
		}
	}

	// Metadata consists of arbitrary name/value pairs for display in the Concourse UI,
	// and may be returned empty if not needed.
	metadata := oc.Metadata{
		// {
		// 	Name:  "a",
		// 	Value: "b",
		// },
		// {
		// 	Name:  "c",
		// 	Value: "d",
		// },
	}

	// Here, `version` is passed through from the argument. In most cases, it makes sense
	// to retrieve the most recent version, i.e. the one in the `version` argument, and
	// then return it back unchanged. However, it is allowed to return some other version
	// or even an empty version, depending on the implementation.
	return version, metadata, nil
}

// Out implements the ofcourse.Resource Out method, corresponding to the /opt/resource/out command.
// This is called when a Concourse job does a `put` on the resource.
func (r *Resource) Out(inputDirectory string, source oc.Source, params oc.Params,
	env oc.Environment, logger *oc.Logger) (oc.Version, oc.Metadata, error) {

	s, err := parseSource(source)
	if err != nil {
		return nil, nil, err
	}

	p, err := parseOutParams(params)
	if err != nil {
		return nil, nil, err
	}

	err = r.configureClient(s)
	if err != nil {
		return nil, nil, err
	}

	rootDir := filepath.Join(inputDirectory, p.Path)

	err = filepath.Walk(rootDir,
		func(path string, info os.FileInfo, err error) error {
			if info.IsDir() {
				return nil
			}

			bytes, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}
			secert := sv.NewSecret()
			err = secert.UnmarshalJSON(bytes)
			if err != nil {
				return err
			}
			secretPath, err := filepath.Rel(rootDir, path)
			if err != nil {
				return err
			}
			return r.client.Write(filepath.Join(p.Prefix, secretPath), secert)
		})
	if err != nil {
		return nil, nil, err
	}

	// Both `version` and `metadata` may be empty. In this case, we are returning
	// `version` retrieved from the file created by `In`, while `metadata` is empty.
	metadata := oc.Metadata{}
	return nil, metadata, nil
}
