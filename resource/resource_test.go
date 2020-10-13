package resource_test

import (
	oc "github.com/cloudboss/ofcourse/ofcourse"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/starkandwayne/vault-concourse-resource/resource"
	"github.com/starkandwayne/vault-concourse-resource/vault"
	"github.com/starkandwayne/vault-concourse-resource/vault/vaultfakes"
)

var _ = Describe("Resource", func() {
	var (
		r          *resource.Resource
		c          *vaultfakes.FakeClient
		url        string
		testLogger = oc.NewLogger(oc.SilentLevel) // TODO: ginko writer logger? https://onsi.github.io/ginkgo/#logging-output
		env        = oc.NewEnvironment()
	)
	BeforeEach(func() {
		c = &vaultfakes.FakeClient{}
		r = &resource.Resource{
			GetClient: func(u string) (vault.Client, error) {
				Expect(u).To(Equal(url))
				return c, nil
			},
		}
	})
	Describe("Check", func() {
		Context("given url, roleid, sercretid", func() {
			It("configures vault client using AuthAppRole", func() {
				c.ListReturnsOnCall(0, []string{"/secret/testpath/secret1", "/secret/testpath/secret2"}, nil)
				c.ListReturnsOnCall(1, []string{"/secret/otherpath/secret3", "/secret/otherpath/secret/4"}, nil)
				url = "http://test.vault"
				response, err := r.Check(oc.Source{
					"url":       "http://test.vault",
					"role_id":   "test_role_id",
					"secret_id": "test_secret_id",
					"paths": []string{
						"/secret/testpath",
						"/secret/otherpath",
					},
				}, oc.Version{}, env, testLogger)
				Expect(err).ToNot(HaveOccurred())
				roleID, secretID := c.AuthApproleArgsForCall(0)
				Expect(roleID).To(Equal("test_role_id"))
				Expect(secretID).To(Equal("test_secret_id"))
				Expect(response).To(Equal([]oc.Version{
					{
						"secret_sha1": "da39a3ee5e6b4b0d3255bfef95601890afd8070",
						"url":         "http://test.vault",
					},
				}))
			})
		})
		Context("when url, roleid, secretid is missing", func() {
			It("configures vault client using AuthAppRole", func() {
				_, err := r.Check(oc.Source{
					"url": "http://test.vault",
					"paths": []string{
						"/secret/testpath",
						"/secreat/testpath/1",
					},
				}, oc.Version{}, env, testLogger)
				Expect(err).To(HaveOccurred())
			})
		})
	})
})
