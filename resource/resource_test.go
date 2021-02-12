package resource_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

	const secretsBytes = `{"ping":"pong", "this":"that", "ying":"yang"}`
	const defaultSecretName = "some_secret"
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

	ocParams := func(secretMaps []interface{}) oc.Params {
		params := oc.Params{
			"path":   "resource_root_path",
			"prefix": prefix,
		}
		if secretMaps != nil {
			params["secret_maps"] = secretMaps
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

	writeFile := func(secretName string) {
		secretNameSplit := strings.Split(secretName, "/")
		nameOnly := secretNameSplit[len(secretNameSplit)-1]
		secretDir := strings.TrimSuffix(secretName, "/"+nameOnly)
		err := os.MkdirAll(secretDir, 0775)
		Expect(err).ToNot(HaveOccurred())
		err = ioutil.WriteFile(secretName, []byte(secretsBytes), 0644)
		Expect(err).ToNot(HaveOccurred())
	}

	createSecretsAndCallOutFunction := func(secretMaps []interface{}) error {
		params := ocParams(secretMaps)
		inDir := filepath.Join(home, "in")

		if secretMaps != nil {
			secretMapsParam := params["secret_maps"].([]interface{})
			for _, secretMapParam := range secretMapsParam {
				secretMapParamMap := secretMapParam.(map[string]interface{})
				sourcePath := (secretMapParamMap["source"]).(string)
				secretDir := filepath.Join(inDir, params["path"].(string), sourcePath)
				writeFile(secretDir)
			}
		} else {
			secretDir := filepath.Join(inDir, params["path"].(string), defaultSecretName)
			writeFile(secretDir)
		}

		_, _, err := r.Out(inDir, oc.Source{
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

	safeSet := func(path, key, value string) ([]byte, error) {
		keyAndValue := strings.Join([]string{key, "=", value}, "")
		s := safe(home, "set", path, keyAndValue)
		s.Stdout = nil
		return s.Output()
	}

	vaultPathContainsExpectedKeysAndValues := func(pathName string, expected map[string]string) {
		for key, value := range expected {
			result, err := safeGet(filepath.Join(prefix, pathName) + ":" + key)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(result)).To(Equal(value + "\n"))
		}
	}

	vaultPathDoesNotContainUnexpectedKeys := func(pathName string, unexpected []string) {
		for _, key := range unexpected {
			_, err := safeGet(filepath.Join(prefix, pathName) + ":" + key)
			Expect(err).To(HaveOccurred())
		}
	}

	createSecretMaps := func(source string, dest string, keys []interface{}) []interface{} {
		return []interface{}{
			map[string]interface{}{
				"source": source,
				"dest":   dest,
				"keys":   keys,
			},
		}
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
		Context("given a vault with secrets", func() {
			It("should import all keys and write them back to the same path when no secret_map is provided", func() {
				err := createSecretsAndCallOutFunction(nil)
				Expect(err).ToNot(HaveOccurred())
				expectedPath := defaultSecretName
				vaultPathContainsExpectedKeysAndValues(expectedPath, map[string]string{"ping": "pong", "this": "that", "ying": "yang"})
			})
			It("should import all keys and write them back to the same path name, retaining original key names", func() {
				secretMaps := createSecretMaps("/some/place", "", nil)
				err := createSecretsAndCallOutFunction(secretMaps)
				Expect(err).ToNot(HaveOccurred())
				expectedPath := (secretMaps[0].(map[string]interface{})["source"]).(string)
				vaultPathContainsExpectedKeysAndValues(expectedPath, map[string]string{"ping": "pong", "this": "that", "ying": "yang"})
			})
			It("should import all keys and write them to the destPath path name, retaining original key names", func() {
				secretMaps := createSecretMaps("/some/place", "/new/place", nil)
				err := createSecretsAndCallOutFunction(secretMaps)
				Expect(err).ToNot(HaveOccurred())
				expectedPath := (secretMaps[0].(map[string]interface{})["dest"]).(string)
				vaultPathContainsExpectedKeysAndValues(expectedPath, map[string]string{"ping": "pong", "this": "that", "ying": "yang"})
			})
			It("should import only specified keys and write them back to the same path name, retaining original key names", func() {
				keys := []interface{}{"ping", "ying"}
				secretMaps := createSecretMaps("/some/place", "", keys)
				err := createSecretsAndCallOutFunction(secretMaps)
				Expect(err).ToNot(HaveOccurred())
				expectedPath := (secretMaps[0].(map[string]interface{})["source"]).(string)
				vaultPathContainsExpectedKeysAndValues(expectedPath, map[string]string{"ping": "pong", "ying": "yang"})
				vaultPathDoesNotContainUnexpectedKeys(expectedPath, []string{"this"})
			})
			It("should import only specified keys, rename them appropriately and write them back to the same path name", func() {
				keys := []interface{}{
					"ping",
					map[string]interface{}{"ying": "yingling"},
					map[string]interface{}{"this": "all"},
				}
				secretMaps := createSecretMaps("/some/place", "", keys)
				err := createSecretsAndCallOutFunction(secretMaps)
				Expect(err).ToNot(HaveOccurred())
				expectedPath := (secretMaps[0].(map[string]interface{})["source"]).(string)
				vaultPathContainsExpectedKeysAndValues(expectedPath, map[string]string{"ping": "pong", "yingling": "yang"})
				vaultPathDoesNotContainUnexpectedKeys(expectedPath, []string{"this"})
			})
			It("should import only specified keys, rename them appropriately and write them back to the destination", func() {
				keys := []interface{}{
					"ping",
					map[string]interface{}{"ying": "yingling"},
				}
				secretMaps := createSecretMaps("/some/place", "/new/place", keys)
				err := createSecretsAndCallOutFunction(secretMaps)
				Expect(err).ToNot(HaveOccurred())
				expectedPath := (secretMaps[0].(map[string]interface{})["dest"]).(string)
				vaultPathContainsExpectedKeysAndValues(expectedPath, map[string]string{"ping": "pong", "yingling": "yang"})
				vaultPathDoesNotContainUnexpectedKeys(expectedPath, []string{"this"})
			})
			It("should import multiple secrets, rename them appropriately and write them back to the destination", func() {
				keys := []interface{}{
					"ping",
					map[string]interface{}{"ying": "yingling"},
				}
				secretMaps := createSecretMaps("/some/place", "/new/place", keys)
				keys2 := []interface{}{
					"ying",
					map[string]interface{}{"this": "lookat"},
				}
				secretMaps2 := createSecretMaps("/other/place", "/othernew/place", keys2)
				secretMaps = append(secretMaps, secretMaps2[0])
				err := createSecretsAndCallOutFunction(secretMaps)
				Expect(err).ToNot(HaveOccurred())

				expectedPath := (secretMaps[0].(map[string]interface{})["dest"]).(string)
				vaultPathContainsExpectedKeysAndValues(expectedPath, map[string]string{"ping": "pong", "yingling": "yang"})
				vaultPathDoesNotContainUnexpectedKeys(expectedPath, []string{"this"})

				expectedPath2 := (secretMaps[1].(map[string]interface{})["dest"]).(string)
				vaultPathContainsExpectedKeysAndValues(expectedPath2, map[string]string{"ying": "yang", "lookat": "that"})
				vaultPathDoesNotContainUnexpectedKeys(expectedPath2, []string{"ping"})
			})
			It("should import  secrets, rename them appropriately and write them to the same destination without removing existing keys", func() {
				keys := []interface{}{
					map[string]interface{}{"ying": "yingling"},
				}
				secretMaps := createSecretMaps("/some/place", "/new/place", keys)
				keys2 := []interface{}{
					map[string]interface{}{"this": "lookat"},
				}
				secretMaps2 := createSecretMaps("/other/place", "/new/place", keys2)
				secretMaps = append(secretMaps, secretMaps2[0])

				_, err := safeSet("/secret/new/place", "hi", "there")
				Expect(err).ToNot(HaveOccurred())

				err = createSecretsAndCallOutFunction(secretMaps)
				Expect(err).ToNot(HaveOccurred())

				expectedPath := (secretMaps[0].(map[string]interface{})["dest"]).(string)
				vaultPathContainsExpectedKeysAndValues(expectedPath, map[string]string{"yingling": "yang", "lookat": "that", "hi": "there"})
			})
			It("should fail gracefully if no source is specified", func() {
				secretMaps := createSecretMaps("", "", nil)
				err := createSecretsAndCallOutFunction(secretMaps)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(BeEquivalentTo("Please provide a source for the secret"))
			})
			It("should fail gracefully if Keys contains a key that doesn't exist", func() {
				keys := []interface{}{"ping", "king", "ting"}
				secretMaps := createSecretMaps("/some/place", "", keys)
				err := createSecretsAndCallOutFunction(secretMaps)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("Specified keys not found in input for secret"))
				Expect(err.Error()).To(ContainSubstring("king"))
				Expect(err.Error()).To(ContainSubstring("ting"))
			})
			It("should fail gracefully if Keys contains a key to be renamed that doesn't exist", func() {
				keys := []interface{}{
					map[string]interface{}{"ping": "pong"},
					map[string]interface{}{"oops": "dang"},
					map[string]interface{}{"king": "queen"},
				}
				secretMaps := createSecretMaps("/some/place", "", keys)
				err := createSecretsAndCallOutFunction(secretMaps)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("Specified keys not found in input for secret"))
				Expect(err.Error()).To(ContainSubstring("oops"))
				Expect(err.Error()).To(ContainSubstring("king"))
				Expect(err.Error()).NotTo(ContainSubstring("ping"))
			})
			It("should fail gracefully if a circular reference exists trying to rename keys", func() {
				keys := []interface{}{
					map[string]interface{}{"ping": "pong"},
					map[string]interface{}{"pong": "pang"},
				}
				secretMaps := createSecretMaps("/some/place", "", keys)
				err := createSecretsAndCallOutFunction(secretMaps)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("Circular reference trying to rename the following keys for secret"))
				Expect(err.Error()).To(ContainSubstring("pong"))
				Expect(err.Error()).NotTo(ContainSubstring("ping"))
				Expect(err.Error()).NotTo(ContainSubstring("this"))
				Expect(err.Error()).NotTo(ContainSubstring(" ying"))
			})
			It("should fail gracefully if Keys contains map with multiple elements", func() {
				keys := []interface{}{
					"ping",
					map[string]interface{}{"ying": "yingling", "oh": "no"},
				}
				secretMaps := createSecretMaps("/some/place", "", keys)
				err := createSecretsAndCallOutFunction(secretMaps)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("Only one key/value pair can be specified in"))
				Expect(err.Error()).To(ContainSubstring("oh:no"))
				Expect(err.Error()).To(ContainSubstring("ying:yingling"))
			})
			It("should import secrets from directory (original test for backward compatibility)", func() {
				inDir := filepath.Join(home, "in")
				secretDir := filepath.Join(inDir, "root/secret")
				err := os.MkdirAll(secretDir, 0775)
				Expect(err).ToNot(HaveOccurred())
				ioutil.WriteFile(filepath.Join(secretDir, "othersecrets"), []byte(`{"ping":"pong"}`), 0644)
				_, _, err = r.Out(inDir, oc.Source{
					"url":   url,
					"token": token,
					"paths": []string{
						"/secret/handshake",
					},
				}, oc.Params{
					"path":   "root/secret",
					"prefix": "secret",
				}, env, testLogger)
				Expect(err).ToNot(HaveOccurred())
				s := safe(home, "get", "/secret/othersecrets:ping")
				s.Stdout = nil
				result, err := s.Output()
				Expect(err).ToNot(HaveOccurred())
				Expect(string(result)).To(Equal("pong\n"))
			})
		})
	})

	AfterEach(func() {
		syscall.Kill(-vault.Process.Pid, syscall.SIGKILL)
		os.RemoveAll(home)
	})
})
