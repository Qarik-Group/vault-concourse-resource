// Package resource is an implementation of a Concourse resource.
package resource

import (
	"encoding/json"
	"errors"
	"fmt"
	oc "github.com/cloudboss/ofcourse/ofcourse"
	sv "github.com/starkandwayne/safe/vault"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
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
		Namespace:  s.Namespace,
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

	if p.SecretMaps == nil {
		var sm SecretMap
		sm.Source = ""
		p.SecretMaps = []SecretMap{sm}
	}

	for _, secretMap := range p.SecretMaps {

		sourceDir := filepath.Join(rootDir, secretMap.Source)
		files, err := listFilesUnder(sourceDir)
		if err != nil {
			return nil, nil, err
		}

		for _, secretFile := range files {
			secret, err := createSecret(sourceDir, secretFile)
			if err != nil {
				return nil, nil, err
			}

			finalKeys, err := getFinalKeys(secretMap.Keys)
			if err != nil {
				return nil, nil, err
			}

			err = validate(secret, finalKeys)
			if err != nil {
				return nil, nil, err
			}

			err = filterAndRenameKeys(secret, finalKeys)
			if err != nil {
				return nil, nil, err
			}

			err = copySecretToVault(r.client, p.Prefix, secretMap.Dest, secretFile, secret)
			if err != nil {
				return nil, nil, err
			}

		}
	}
	// Both `version` and `metadata` may be empty. In this case, we are returning
	// `version` retrieved from the file created by `In`, while `metadata` is empty.
	metadata := oc.Metadata{}
	return nil, metadata, nil
}

func listFilesUnder(rootDir string) ([]string, error) {
	ret := []string{}
	err := filepath.Walk(rootDir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			secretPath, err := filepath.Rel(rootDir, path)
			if err != nil {
				return err
			}
			ret = append(ret, secretPath)
			return nil
		},
	)
	return ret, err
}

func createSecret(rootDir string, secretFile string) (*sv.Secret, error) {
	srcFile, err := os.Open(filepath.Join(rootDir, secretFile))
	if err != nil {
		return nil, fmt.Errorf("Error reading source file '%s': %s", secretFile, err)
	}
	jDec := json.NewDecoder(srcFile)
	secret := sv.NewSecret()
	err = jDec.Decode(&secret)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func validate(secret *sv.Secret, finalKeys map[string]string) error {
	aKeyIsMissing := false
	missingKeys := []string{}
	keys := make([]string, 0, len(finalKeys))
	values := make([]string, 0, len(finalKeys))
	var sb strings.Builder
	for key, value := range finalKeys {
		keys = append(keys, key)
		values = append(values, value)
		if !secret.Has(key) {
			aKeyIsMissing = true
			missingKeys = append(missingKeys, key)
		}
	}

	illegalKeys := []string{}
	illegalKeysFound := false
	for _, value := range values {
		for _, key := range keys {
			if key == value {
				illegalKeys = append(illegalKeys, key)
			}
		}
	}
	if illegalKeysFound {
		sb.WriteString("Circular reference trying to rename keys: ")
		sb.WriteString(strings.Join(illegalKeys, ","))
		return fmt.Errorf(sb.String())
	}

	if aKeyIsMissing {
		sb.WriteString("Specified keys not found: ")
		sb.WriteString(strings.Join(missingKeys, ","))
		return fmt.Errorf(sb.String())
	}

	return nil
}

func filterAndRenameKeys(secret *sv.Secret, finalKeys map[string]string) error {
	if len(finalKeys) == 0 {
		return nil
	}
	for _, currentKey := range secret.Keys() {
		finalKey, exists := finalKeys[currentKey]
		if exists {
			value := secret.Get(currentKey)
			err := secret.Set(finalKey, value, false)
			if err != nil {
				return err
			}
		}
		if (!exists) || (finalKey != currentKey) {
			secret.Delete(currentKey)
		}
	}
	return nil
}

func copySecretToVault(client *sv.Vault, prefix string, dest string, secretPath string, secret *sv.Secret) error {
	finalDest := filepath.Join(prefix, dest, secretPath)
	return client.Write(finalDest, secret)
}

func getFinalKeys(keys []interface{}) (map[string]string, error) {
	finalKeys := map[string]string{}
	for _, key := range keys {
		switch v := key.(type) {
		case string:
			keyString := fmt.Sprintf("%v", key)
			finalKeys[keyString] = keyString
		case map[string]string:
			if len(v) > 1 {
				return nil, fmt.Errorf("Only one key/value pair can be specified in %s", v)
			}
			for key, value := range v {
				finalKeys[key] = value
			}
		default:
			// do nothing
		}
	}
	return finalKeys, nil
}
