package main

import (
	"github.com/starkandwayne/vault-concourse-resource/resource"
	"github.com/cloudboss/ofcourse/ofcourse"
)

func main() {
	ofcourse.In(&resource.Resource{})
}
