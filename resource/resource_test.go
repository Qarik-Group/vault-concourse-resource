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

	const prefix = "secret"

	safe := func(home string, args ...string) *exec.Cmd {
		cmd := exec.Command("safe", args...)
		cmd.Stdout = GinkgoWriter
		cmd.Stderr = GinkgoWriter
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("HOME=%s", home),
		)
		return cmd
	}

	ocParams := func(steves []interface{}) oc.Params {
		params := oc.Params{
			"path":   "resource_root_path",
			"prefix": prefix,
		}
		if steves != nil {
			params["steves"] = steves
		}
		return params
	}

	getCurrentVaultTarget := func(home string) (string, string) {
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

	createSecretsAndCallOutFunction := func(secretsBytes string, params oc.Params) error {
		inDir := filepath.Join(home, "in")

		//namePath = params["steves"].([]interface{})[0].(map[string]string)["name"] // too damn ugly
		stevesParam := params["steves"].([]interface{})
		steveParam := stevesParam[0].(map[string]string)
		namePath := steveParam["name"]

		secretDir := filepath.Join(inDir, params["path"].(string), namePath)
		err := os.MkdirAll(secretDir, 0775)
		Expect(err).ToNot(HaveOccurred())
		filename := filepath.Join(secretDir, "othersecrets")
		ioutil.WriteFile(filename, []byte(secretsBytes), 0644)
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

	vaultPathContainsExpectedKeysAndValues := func(pathName string, expected map[string]string) {
		for key, value := range expected {
			result, err := safeGet(filepath.Join(prefix, pathName, "othersecrets") + ":" + key)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(result)).To(Equal(value + "\n"))
		}
	}

	// TODO add keys param and "keys" key
	createSteves := func(name string, dest string) []interface{} {
		return []interface{}{
			map[string]string{"name": name, "dest": dest},
		}
	}

	// TODO add this back in to tests
	//vaultPathDoesNotContainUnexpectedKeys := func(pathName string, unexpected []string) {
	//	for _, key := range unexpected {
	//		_, err := safeGet(pathName + ":"  + key)
	//		Expect(err).To(HaveOccurred())
	//	}
	//}

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
		Context("given a vault with secrets", func() {
			It("should import all secrets and write them back to the same path name, retaining original key names", func() {
				steves := createSteves("/some/place", "")
				err := createSecretsAndCallOutFunction(
					secretsBytes,
					ocParams(steves),
				)
				Expect(err).ToNot(HaveOccurred())
				expectedPath := steves[0].(map[string]string)["name"]
				vaultPathContainsExpectedKeysAndValues(expectedPath, map[string]string{"ping": "pong", "this": "that", "ying": "yang"})
			})
			It("should import all secrets and write them to the destPath path name, retaining original key names", func() {
				steves := createSteves("/some/place", "/new/place")
				params := ocParams(steves)
				err := createSecretsAndCallOutFunction(
					secretsBytes,
					params,
				)
				Expect(err).ToNot(HaveOccurred())
				expectedPath := steves[0].(map[string]string)["dest"]
				vaultPathContainsExpectedKeysAndValues(expectedPath, map[string]string{"ping": "pong", "this": "that", "ying": "yang"})
			})
			It("should fail gracefully if no name is specified", func() {
				steves := createSteves("", "")
				err := createSecretsAndCallOutFunction(
					secretsBytes,
					ocParams(steves),
				)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(BeEquivalentTo("Please provide a source for the secret"))
			})
			//It("should import all secrets from directory and retain original key names", func() {
			//	err := createSecretsAndCallOutFunction(
			//		secretsBytes,
			//		ocParams(nil),
			//	)
			//	Expect(err).ToNot(HaveOccurred())
			//	vaultPathContainsExpectedKeysAndValues(map[string]string{"ping": "pong", "this": "that", "ying": "yang"})
			//})
			//It("should import only specified secrets from directory and name them appropriately", func() {
			//	err := createSecretsAndCallOutFunction(
			//		secretsBytes,
			//		ocParams(
			//			[]interface{}{
			//				"ping",
			//				map[string]string{"ying": "yingling"},
			//			}),
			//	)
			//	Expect(err).ToNot(HaveOccurred())
			//	vaultPathContainsExpectedKeysAndValues(map[string]string{"ping": "pong", "yingling": "yang"})
			//	vaultPathDoesNotContainUnexpectedKeys([]string{"this"})
			//})
			//It("should import multiple secrets from directory and retain the original key names", func() {
			//	err := createSecretsAndCallOutFunction(
			//		secretsBytes,
			//		ocParams([]interface{}{"ying", "this"}),
			//	)
			//	Expect(err).ToNot(HaveOccurred())
			//	vaultPathContainsExpectedKeysAndValues(map[string]string{"ying": "yang", "this": "that"})
			//	vaultPathDoesNotContainUnexpectedKeys([]string{"ping"})
			//})
			//It("should import one secrets from directory and retain the original key names", func() {
			//	err := createSecretsAndCallOutFunction(
			//		secretsBytes,
			//		ocParams([]interface{}{"ping"}),
			//	)
			//	Expect(err).ToNot(HaveOccurred())
			//	vaultPathContainsExpectedKeysAndValues(map[string]string{"ping": "pong"})
			//	vaultPathDoesNotContainUnexpectedKeys([]string{"ying", "this"})
			//})
			//It("should fail gracefully if Keys contains a key that doesn't exist", func() {
			//	err := createSecretsAndCallOutFunction(
			//		secretsBytes,
			//		ocParams([]interface{}{"ping", "sing"}),
			//	)
			//	Expect(err).To(HaveOccurred())
			//	Expect(err.Error()).To(BeEquivalentTo("Specified keys not found: 'sing'"))
			//})
			//It("\"should fail gracefully if Keys contains a key to be renamed that doesn't exist", func() {
			//	err := createSecretsAndCallOutFunction(
			//		secretsBytes,
			//		ocParams(
			//			[]interface{}{
			//				map[string]string{"ping": "pong", "oops": "dang"},
			//			}),
			//	)
			//	Expect(err).To(HaveOccurred())
			//	Expect(err.Error()).To(BeEquivalentTo("Specified keys not found: 'oops'"))
			//})
		})
	})

	AfterEach(func() {
		syscall.Kill(-vault.Process.Pid, syscall.SIGKILL)
		os.RemoveAll(home)
	})
})
