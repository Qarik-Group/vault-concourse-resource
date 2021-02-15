// Package resource is an implementation of a Concourse resource.
package resource

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

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
	ocVersion, err := r.constructVersion(s, version)
	if err != nil {
		return nil, err
	}
	return []oc.Version{ocVersion}, nil
}

func (r *Resource) constructVersion(s Source, version oc.Version) (oc.Version, error) {
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
	if err != nil {
		return nil, err
	}
	newVersion := newVersion(raw, s.URL)
	if version != nil {
		oldVersion, err := parseVersion(version)
		if err != nil {
			return nil, err
		}
		if oldVersion.equal(newVersion) {
			return oc.Version{}, nil
		}
	}
	return newVersion.toOCVersion(), nil
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

	files, err := listFilesUnder(rootDir)
	if err != nil {
		return nil, nil, err
	}

	if len(p.SecretMaps) == 0 {
		for _, file := range files {
			p.SecretMaps = append(p.SecretMaps, SecretMap{Source: file})
		}
	}

	for _, secretMap := range p.SecretMaps {
		if secretMap.Dest == "" {
			secretMap.Dest = secretMap.Source
		}

		sourceFile := filepath.Join(rootDir, secretMap.Source)

		secret, err := createSecret(sourceFile)
		if err != nil {
			return nil, nil, err
		}

		finalKeys, err := getFinalKeys(secretMap.Keys)
		if err != nil {
			return nil, nil, err
		}

		err = validate(secret, finalKeys, secretMap.Source)
		if err != nil {
			return nil, nil, err
		}

		secretToWrite := filterAndRenameKeys(secret, finalKeys)
		if err != nil {
			return nil, nil, err
		}

		finalVaultPath := filepath.Join(p.Prefix, secretMap.Dest)
		retainExistingKeys(r.client, finalVaultPath, secretToWrite)

		err = copySecretToVault(r.client, finalVaultPath, secretToWrite)
		if err != nil {
			return nil, nil, err
		}

	}
	// Both `version` and `metadata` may be empty. In this case, we are returning
	// `version` just as we do from `Check`, while `metadata` is empty.
	ocVersion, err := r.constructVersion(s, nil)
	if err != nil {
		return nil, nil, err
	}
	metadata := oc.Metadata{}
	return ocVersion, metadata, nil
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

func createSecret(secretFile string) (*sv.Secret, error) {
	srcFile, err := os.Open(secretFile)
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

func validate(secret *sv.Secret, finalKeys map[string]string, source string) error {
	if len(finalKeys) == 0 {
		return nil
	}

	destKeyRefs := map[string]int{}
	thereAreDuplicateDestKeys := false
	missingKeysDedup := map[string]bool{}

	for srcKey, destKey := range finalKeys {
		if destKeyRefs[destKey] > 0 {
			thereAreDuplicateDestKeys = true
		}
		destKeyRefs[destKey]++

		if !secret.Has(srcKey) {
			missingKeysDedup[srcKey] = true
		}
	}

	errorMessages := []string{}

	//The logic here is sort of weird, but its all to dedup in the case that a
	// key is referenced, say, three times (and then sort it to have a
	// deterministic error ordering)
	if thereAreDuplicateDestKeys {
		duplicateDestKeys := []string{}
		for destKey, refCount := range destKeyRefs {
			if refCount > 1 {
				duplicateDestKeys = append(duplicateDestKeys, destKey)
			}
		}
		sort.Strings(duplicateDestKeys)
		errorMessages = append(errorMessages,
			fmt.Sprintf("Reused destination keys when copying secret `%s': %s",
				source,
				strings.Join(duplicateDestKeys, ","),
			),
		)
	}

	if len(missingKeysDedup) > 0 {
		missingKeys := []string{}
		for srcKey := range missingKeysDedup {
			missingKeys = append(missingKeys, srcKey)
		}
		sort.Strings(missingKeys)
		errorMessages = append(errorMessages,
			fmt.Sprintf("Specified keys not found in input for secret `%s': %s",
				source,
				strings.Join(missingKeys, ","),
			),
		)
	}

	if len(errorMessages) > 0 {
		return fmt.Errorf("%s", strings.Join(errorMessages, "\n"))
	}

	return nil
}

func filterAndRenameKeys(secret *sv.Secret, finalKeys map[string]string) *sv.Secret {
	if len(finalKeys) == 0 {
		return secret
	}

	ret := sv.NewSecret()

	for srcKey, destKey := range finalKeys {
		ret.Set(destKey, secret.Get(srcKey), false)
	}

	return ret
}

func copySecretToVault(client *sv.Vault, finalVaultPath string, newSecret *sv.Secret) error {
	return client.Write(finalVaultPath, newSecret)
}

func retainExistingKeys(client *sv.Vault, finalVaultPath string, newSecret *sv.Secret) {
	existingSecret, err := client.Read(finalVaultPath)
	if err == nil {
		for _, existingKey := range existingSecret.Keys() {
			if !newSecret.Has(existingKey) {
				newSecret.Set(existingKey, existingSecret.Get(existingKey), false)
			}
		}
	}
}

func getFinalKeys(keys []interface{}) (map[string]string, error) {
	finalKeys := map[string]string{}
	for _, key := range keys {
		switch v := key.(type) {
		case string:
			finalKeys[v] = v
		case map[string]interface{}:
			if len(v) > 1 {
				return nil, fmt.Errorf("Only one key/value pair can be specified in %s", v)
			}
			for key, value := range v {
				valueString, isString := value.(string)
				if !isString {
					return nil, fmt.Errorf("Value in key map for key `%s' should be of type string", key)
				}

				finalKeys[key] = valueString
			}
		default:
			return nil, fmt.Errorf("The secret_map keys field can contain combinations of strings and key/value pairs. It cannot contain %s", reflect.TypeOf(key))
		}
	}
	return finalKeys, nil
}
