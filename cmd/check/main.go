package main

import (
	"github.com/cloudboss/ofcourse/ofcourse"
	"github.com/starkandwayne/vault-concourse-resource/resource"
)

func main() {
	ofcourse.Check(&resource.Resource{
		GetClient: resource.GetRealVaultClient,
	})
}
