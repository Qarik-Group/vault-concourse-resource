// Package resource is an implementation of a Concourse resource.
package resource

import (
	"crypto/sha1"
	"fmt"

	oc "github.com/cloudboss/ofcourse/ofcourse"
	"github.com/mitchellh/mapstructure"
)

// Recursivly read all files from path and write to vault
type OutParams struct {
	Path   string `mapstructure:"path"`
	Prefix string `mapstructure:"prefix"`
}

type Source struct {
	URL      string   `mapstructure:"url"`
	Token    string   `mapstructure:"token"`
	RoleID   string   `mapstructure:"role_id"`
	SecretID string   `mapstructure:"secret_id"`
	CaCert   string   `mapstructure:"ca_cert,omitempty"`
	Paths    []string `mapstructure:"paths"`
}

type Version struct {
	SecretSHA1 string `mapstructure:"secret_sha1"`
	URL        string `mapstructure:"url"`
}

func validateField(field string, values ...string) error {
	if len(values) == 0 || values[0] == "" {
		return fmt.Errorf("Missing %s field", field)
	}

	return nil
}

func parseOutParams(p oc.Params) (OutParams, error) {
	var result OutParams
	err := mapstructure.Decode(p, &result)
	if err := validateField("path", result.Path); err != nil {
		return OutParams{}, err
	}

	return result, err
}

func parseSource(s oc.Source) (Source, error) {
	var result Source
	err := mapstructure.Decode(s, &result)
	if err := validateField("url", result.URL); err != nil {
		return Source{}, err
	}
	if result.RoleID != "" { // TODO: handle case when only secretid is set
		if err := validateField("role_id", result.RoleID); err != nil {
			return Source{}, err
		}
		if err := validateField("secret_id", result.SecretID); err != nil {
			return Source{}, err
		}
	} else {
		if err := validateField("token", result.Token); err != nil {
			return Source{}, err
		}
	}
	if err := validateField("paths", result.Paths...); err != nil {
		return Source{}, err
	}

	return result, err
}

func (version Version) toOCVersion() oc.Version {
	return oc.Version{
		"secret_sha1": version.SecretSHA1,
		"url":         version.URL,
	}
}

func parseVersion(v oc.Version) (Version, error) {
	var result Version
	err := mapstructure.Decode(v, &result)

	return result, err
}

func newVersion(bytesToSha1 []byte, url string) Version {
	return Version{
		SecretSHA1: fmt.Sprintf("%x", sha1.Sum(bytesToSha1)),
		URL:        url,
	}
}

func (version Version) equal(v Version) bool {
	return version.SecretSHA1 == v.SecretSHA1 && version.URL == v.URL
}
