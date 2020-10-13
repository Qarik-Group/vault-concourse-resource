// Package resource is an implementation of a Concourse resource.
package resource

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"

	oc "github.com/cloudboss/ofcourse/ofcourse"
	"github.com/starkandwayne/vault-concourse-resource/vault"
)

var (
	// ErrVersion means version map is malformed
	ErrVersion = errors.New(`key "count" not found in version map`)
	// ErrParam means parameters are malformed
	ErrParam = errors.New(`missing "version_path" parameter`)
)

// Resource implements the ofcourse.Resource interface.
type Resource struct {
	GetClient func(string) (vault.Client, error)
	client    vault.Client
}

func (r *Resource) configureClient(s Source) error {
	c, err := r.GetClient(s.URL)
	if err != nil {
		return err
	}
	_, err = c.AuthApprole(s.RoleID, s.SecretID)
	r.client = c

	return err
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
	// TODO: for loop over paths
	secrets := make([]string, 0)
	for _, p := range s.Paths {
		s, err := r.client.List(p)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, s...)
	}

	// TODO: iterate over mounts
	// TODO: deal with v2 vs v1
	// TODO: recursivly get the values
	// secrets, err := r.client.List(s.Paths[0])
	// if err != nil {
	// 	return nil, err
	// }
	// sort.Slice(secrets, func(i, j int) bool {
	// return credentials.Credentials[i].Name < credentials.Credentials[j].Name
	// })
	// raw, err := json.Marshal(secrets)
	// if err != nil {
	// 	return nil, err
	// }

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
	// Demo of logging. Resources should never use fmt.Printf or anything that writes
	// to standard output, as it will corrupt the JSON output expected by Concourse.
	logger.Errorf("This is an error")
	logger.Warnf("This is a warning")
	logger.Infof("This is an informational message")
	logger.Debugf("This is a debug message")

	// Write the `version` argument to a file in the output directory,
	// so the `Out` function can read it.
	outputPath := fmt.Sprintf("%s/version", outputDirectory)
	bytes, err := json.Marshal(version)
	if err != nil {
		return nil, nil, err
	}
	logger.Debugf("Version: %s", string(bytes))

	err = ioutil.WriteFile(outputPath, bytes, 0644)
	if err != nil {
		return nil, nil, err
	}

	// Metadata consists of arbitrary name/value pairs for display in the Concourse UI,
	// and may be returned empty if not needed.
	metadata := oc.Metadata{
		{
			Name:  "a",
			Value: "b",
		},
		{
			Name:  "c",
			Value: "d",
		},
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
	// The `Out` function does not receive a `version` argument. Instead, we
	// will read the version from the file created by the `In` function, assuming
	// the pipeline does a `get` of this resource. The path to the version file
	// must be passed in the `put` parameters.
	versionPath, ok := params["version_path"]
	if !ok {
		return nil, nil, ErrParam
	}

	// The `inputDirectory` argument is a directory containing subdirectories for
	// all resources retrieved with `get` in a job, as well as all of the job's
	// task outputs.
	path := fmt.Sprintf("%s/%s", inputDirectory, versionPath)
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	var version oc.Version
	err = json.Unmarshal(bytes, &version)
	if err != nil {
		return nil, nil, err
	}

	// Both `version` and `metadata` may be empty. In this case, we are returning
	// `version` retrieved from the file created by `In`, while `metadata` is empty.
	metadata := oc.Metadata{}
	return version, metadata, nil
}
