package resource_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	oc "github.com/cloudboss/ofcourse/ofcourse"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/starkandwayne/vault-concourse-resource/resource"
	"gopkg.in/yaml.v2"
)

func safe(home string, args ...string) *exec.Cmd {
	cmd := exec.Command("safe", args...)
	cmd.Stdout = GinkgoWriter
	cmd.Stderr = GinkgoWriter
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("HOME=%s", home),
	)
	return cmd
}

func getCurrentVaultTarget(home string) (string, string) {
	config := struct {
		Current string                       `yaml:"current"`
		Vaults  map[string]map[string]string `yaml:"vaults"`
	}{}
	raw, err := ioutil.ReadFile(filepath.Join(home, ".saferc"))
	Expect(err).ToNot(HaveOccurred())
	err = yaml.Unmarshal(raw, &config)
	Expect(err).ToNot(HaveOccurred())
	return config.Vaults[config.Current]["url"], config.Vaults[config.Current]["token"]
}

func ocParams(keys []string, rename []string) oc.Params {
	params := oc.Params{
		"path":   "root/secret",
		"prefix": "secret",
	}
	if keys != nil {
		params["keys_to_copy"] = keys
	}
	if rename != nil {
		params["renamed_to"] = rename
	}
	return params
}

var _ = Describe("Resource", func() {
	var (
		vault      *exec.Cmd
		home       string
		r          = &resource.Resource{}
		url        string
		token      string
		env        = oc.NewEnvironment()
		testLogger = oc.NewLogger(oc.SilentLevel) // TODO: cannot use ginkgo.GinkgoWriter (type io.Writer) as type *ofcourse.Logger ginko writer logger? https://onsi.github.io/ginkgo/#logging-output
	)

	createSecretsAndCallOutFunction := func(secretsBytes string, params oc.Params) error {
		inDir := filepath.Join(home, "in")
		secretDir := filepath.Join(inDir, "root/secret")
		err := os.MkdirAll(secretDir, 0775)
		Expect(err).ToNot(HaveOccurred())
		ioutil.WriteFile(filepath.Join(secretDir, "othersecrets"), []byte(secretsBytes), 0644)
		_, _, err = r.Out(inDir, oc.Source{
			"url":   url,
			"token": token,
			"paths": []string{
				"/secret/handshake",
			},
		}, params, env, testLogger)
		return err
	}

	safeGet := func(keyWithPath string) ([]byte, error) {
		s := safe(home, "get", keyWithPath)
		s.Stdout = nil
		return s.Output()
	}

	BeforeEach(func() {
		var err error
		home, err = ioutil.TempDir("", "vault-concourse-home")
		Expect(err).ToNot(HaveOccurred())
		vault = safe(home, "local", "--memory")
		err = vault.Start()
		Expect(err).ToNot(HaveOccurred())

		Eventually(func() int {
			s := safe(home, "get", "secret/handshake")
			s.Run()
			return s.ProcessState.ExitCode()
		}, "5s", "500ms").Should(Equal(0))
		url, token = getCurrentVaultTarget(home)
	})
	Describe("Check", func() {
		Context("given a vault with secrets", func() {
			It("should check version", func() {
				response, err := r.Check(oc.Source{
					"url":   url,
					"token": token,
					"paths": []string{
						"/secret/handshake",
					},
				}, oc.Version{}, env, testLogger)
				Expect(err).ToNot(HaveOccurred())
				Expect(response).To(Equal([]oc.Version{
					{
						"secret_sha1": "775fb98067bd6a203dc835a1dcf2f7169f43e372",
						"url":         "http://127.0.0.1:8201",
					},
				}))
			})
		})
	})
	Describe("In", func() {
		Context("given a vault with secrets", func() {
			It("should export secrets to directory", func() {
				outDir := filepath.Join(home, "out")
				_, _, err := r.In(outDir, oc.Source{
					"url":   url,
					"token": token,
					"paths": []string{
						"/secret/handshake",
					},
				}, oc.Params{}, oc.Version{}, env, testLogger)
				Expect(err).ToNot(HaveOccurred())
				result, err := ioutil.ReadFile(filepath.Join(outDir, "secret/handshake"))
				Expect(string(result)).To(Equal(`{"knock":"knock"}`))
			})
		})
	})
	Describe("Out", func() {
		const secretsBytes = `{"ping":"pong", "this":"that", "ying":"yang"}`
		const othersecretsPath = "/secret/othersecrets:"
		Context("given a vault with secrets", func() {
			It("should import all secrets from directory and retain original key names", func() {
				err := createSecretsAndCallOutFunction(
					secretsBytes,
					ocParams(nil, nil),
				)
				Expect(err).ToNot(HaveOccurred())
				//TODO extract this to a method:
				expected := map[string]string{"ping": "pong", "this": "that", "ying": "yang"}
				for key, value := range expected {
					result, err := safeGet(othersecretsPath + key)
					Expect(err).ToNot(HaveOccurred())
					Expect(string(result)).To(Equal(value + "\n"))
				}
			})
			It("should import only specified secrets from directory and name them appropriately", func() {
				err := createSecretsAndCallOutFunction(
					secretsBytes,
					ocParams([]string{"ping", "ying"}, []string{"ping", "yingling"}),
				)
				Expect(err).ToNot(HaveOccurred())
				expected := map[string]string{"ping": "pong", "yingling": "yang"}
				for key, value := range expected {
					result, err := safeGet(othersecretsPath + key)
					Expect(err).ToNot(HaveOccurred())
					Expect(string(result)).To(Equal(value + "\n"))
				}
				_, err = safeGet(othersecretsPath + "this")
				Expect(err).To(HaveOccurred())
			})
			It("should import specified secrets from directory and retain the original key names", func() {
				err := createSecretsAndCallOutFunction(
					secretsBytes,
					ocParams([]string{"ping", "ying"}, nil),
				)
				Expect(err).ToNot(HaveOccurred())
				expected := map[string]string{"ping": "pong", "ying": "yang"}
				for key, value := range expected {
					result, err := safeGet(othersecretsPath + key)
					Expect(err).ToNot(HaveOccurred())
					Expect(string(result)).To(Equal(value + "\n"))
				}
			})
			It("should ignore renamed_to if keys_to_copy is not specified", func() {
				err := createSecretsAndCallOutFunction(
					secretsBytes,
					ocParams(nil, []string{"ping", "yingling"}),
				)
				Expect(err).ToNot(HaveOccurred())
				expected := map[string]string{"ping": "pong", "ying": "yang"}
				for key, value := range expected {
					result, err := safeGet(othersecretsPath + key)
					Expect(err).ToNot(HaveOccurred())
					Expect(string(result)).To(Equal(value + "\n"))
				}
			})
			It("should fail gracefully if keys_to_copy and renamed_to have a different number of values", func() {
				err := createSecretsAndCallOutFunction(
					secretsBytes,
					ocParams([]string{"ping", "ying"}, []string{"thing"}),
				)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(BeEquivalentTo("keys_to_copy and renamed_to must have the same number of values"))
			})
			It("should fail gracefully if keys_to_copy contains a key that doesn't exist", func() {
				err := createSecretsAndCallOutFunction(
					secretsBytes,
					ocParams([]string{"ping", "sing"}, nil),
				)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(BeEquivalentTo("sing not found"))
			})
		})
	})

	AfterEach(func() {
		syscall.Kill(-vault.Process.Pid, syscall.SIGKILL)
		os.RemoveAll(home)
	})
})
