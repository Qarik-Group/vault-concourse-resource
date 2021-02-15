package resource_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	oc "github.com/cloudboss/ofcourse/ofcourse"
	"github.com/onsi/ginkgo"
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

	safeGet := func(keyWithPath string) ([]byte, error) {
		s := safe(home, "get", keyWithPath)
		s.Stdout = nil
		return s.Output()
	}

	safeSet := func(path string, kv map[string]string) ([]byte, error) {
		kvArgs := []string{"set", path}
		for k, v := range kv {
			kvArgs = append(kvArgs, fmt.Sprintf("%s=%s", k, v))
		}

		s := safe(home, kvArgs...)
		s.Stdout = nil
		return s.Output()
	}

	seedSecrets := func() {
		type vaultSecret struct {
			path   string
			values map[string]string
		}
		values := map[string]string{
			"ping": "pong",
			"this": "that",
			"ying": "yang",
		}
		secrets := []vaultSecret{
			{path: "/some/place", values: values},
			{path: "/other/place", values: values},
		}

		resourceRootDir := filepath.Join(home, "in/resource_root_path")
		for _, secret := range secrets {
			_, err := safeSet(filepath.Join("secret", secret.path), values)
			Expect(err).NotTo(HaveOccurred())

			writePath := filepath.Join(resourceRootDir, secret.path)
			err = os.MkdirAll(filepath.Dir(writePath), 0775)
			Expect(err).NotTo(HaveOccurred())
			f, err := os.Create(writePath)
			Expect(err).NotTo(HaveOccurred())
			jEnc := json.NewEncoder(f)
			err = jEnc.Encode(&secret.values)
			Expect(err).NotTo(HaveOccurred())
		}
	}

	cleanupSecrets := func() {
		Expect(strings.HasPrefix(home, "/tmp")).To(BeTrue())
		err := os.RemoveAll(home)
		Expect(err).NotTo(HaveOccurred())
	}

	callOutFunction := func(secretMaps []interface{}) error {
		params := ocParams(secretMaps)
		inDir := filepath.Join(home, "in")

		_, _, err := r.Out(inDir, oc.Source{
			"url":   url,
			"token": token,
			"paths": []string{
				"/secret/handshake",
			},
		}, params, env, testLogger)

		return err
	}

	vaultPathContainsExpectedKeysAndValues := func(pathName string, expected map[string]string) {
		ginkgo.GinkgoWriter.Write([]byte("testing expected keys and values"))
		result, err := safeGet(filepath.Join(prefix, pathName))
		Expect(err).NotTo(HaveOccurred())
		ginkgo.GinkgoWriter.Write(result)
		for key, value := range expected {
			result, err := safeGet(filepath.Join(prefix, pathName) + ":" + key)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(result)).To(Equal(value + "\n"))
		}
	}

	vaultPathDoesNotContainUnexpectedKeys := func(pathName string, unexpected []string) {
		for _, key := range unexpected {
			_, err := safeGet(filepath.Join(prefix, pathName) + ":" + key)
			Expect(err).To(HaveOccurred(), fmt.Sprintf("found unexpected key: %s", key))
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

	calcExpectedPath := func(src, dest string) string {
		expectedPath := "some/place"
		if dest != "" {
			expectedPath = dest
		} else if src != "" {
			expectedPath = src
		}

		return expectedPath
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
			var paramSrcPath, paramDestPath string
			var paramKeys []interface{}
			var expectedPath string
			var inputSecretMap []interface{}
			var skipOutErrCheck bool
			var outErr error
			var skipCreateSecretMap bool

			BeforeEach(func() {
				paramSrcPath = ""
				paramDestPath = ""
				paramKeys = nil
				inputSecretMap = nil
				expectedPath = defaultSecretName
				skipOutErrCheck = false
				outErr = nil
				skipCreateSecretMap = false
				seedSecrets()
			})

			AfterEach(func() {
				cleanupSecrets()
			})

			JustBeforeEach(func() {
				if !skipCreateSecretMap {
					inputSecretMap = createSecretMaps(
						paramSrcPath,
						paramDestPath,
						paramKeys,
					)
				}
				jEnc := json.NewEncoder(ginkgo.GinkgoWriter)
				err := jEnc.Encode(inputSecretMap)
				Expect(err).NotTo(HaveOccurred())

				outErr = callOutFunction(inputSecretMap)
				if !skipOutErrCheck {
					Expect(outErr).NotTo(HaveOccurred())
				}
				expectedPath = calcExpectedPath(paramSrcPath, paramDestPath)
			})

			When("No secret_map is provided", func() {
				BeforeEach(func() { skipCreateSecretMap = true })
				It("should import all keys and write them back to the same path", func() {
					vaultPathContainsExpectedKeysAndValues(expectedPath, map[string]string{"ping": "pong", "this": "that", "ying": "yang"})
				})
			})

			When("A single secret path is selected", func() {
				BeforeEach(func() {
					paramSrcPath = "/some/place"
				})
				When("No dest path is given", func() {
					When("No key list is given", func() {
						It("should import all keys and write them back to the same path name, retaining original key names", func() {
							vaultPathContainsExpectedKeysAndValues(expectedPath, map[string]string{"ping": "pong", "this": "that", "ying": "yang"})
						})
					})

					When("A key list with no renames which is a subset of the keys in the source secret is given", func() {
						BeforeEach(func() { paramKeys = []interface{}{"ping", "ying"} })
						It("should import only specified keys and write them back to the same path name, retaining original key names", func() {
							By("copying all the keys in the key list")
							vaultPathContainsExpectedKeysAndValues(expectedPath, map[string]string{"ping": "pong", "ying": "yang", "this": "that"})
						})
					})

					When("A key list with renames is given", func() {
						BeforeEach(func() {
							paramKeys = []interface{}{
								"ping",
								map[string]interface{}{"ying": "yingling"},
								map[string]interface{}{"this": "all"},
							}
						})

						It("should rename keys appropriately and write them back to the same path name", func() {
							By("copying all the keys in the key list")
							vaultPathContainsExpectedKeysAndValues(expectedPath, map[string]string{"ping": "pong", "yingling": "yang", "all": "that"})
						})
					})
				})

				When("A destination which is different than the src path is selected", func() {
					BeforeEach(func() { paramDestPath = "/new/place" })

					When("No key list is given", func() {
						It("should import all keys and write them to the set destination, retaining original key names", func() {
							vaultPathContainsExpectedKeysAndValues(expectedPath, map[string]string{"ping": "pong", "this": "that", "ying": "yang"})
						})
					})

					When("A key list with renames which is a subset of the keys in the source secret is given", func() {
						BeforeEach(func() {
							paramKeys = []interface{}{
								"ping",
								map[string]interface{}{"ying": "yingling"},
							}

							It("should import only specified keys, rename them appropriately and write them to the destination path", func() {
								By("copying all the keys in the key list")
								vaultPathContainsExpectedKeysAndValues(expectedPath, map[string]string{"ping": "pong", "yingling": "yang"})
								By("not copying to any of the destination keys not in the key list")
								vaultPathDoesNotContainUnexpectedKeys(expectedPath, []string{"yang", "this"})
							})
						})
					})
				})
			})

			When("multiple secret maps are specified", func() {
				var paramKeys1, paramKeys2 []interface{}
				var expectedPath1, expectedPath2 string
				const src1, src2 = "/some/place", "/other/place"
				const dest1, dest2 = "/new/place", "/othernew/place"

				BeforeEach(func() {
					skipCreateSecretMap = true
					paramKeys1, paramKeys2 = nil, nil
					expectedPath1 = dest1
					expectedPath2 = dest2
				})

				When("keys are being renamed", func() {
					BeforeEach(func() {
						paramKeys1 = []interface{}{
							"ping",
							map[string]interface{}{"ying": "yingling"},
						}
						paramKeys2 = []interface{}{
							"ying",
							map[string]interface{}{"this": "lookat"},
						}
						inputSecretMap = append(
							createSecretMaps(src1, dest1, paramKeys1),
							createSecretMaps(src2, dest2, paramKeys2)...,
						)
					})

					It("should import multiple secrets, rename them appropriately and write them back to the destinations", func() {
						By("copying all the keys in the key list for the first secret")
						vaultPathContainsExpectedKeysAndValues(expectedPath1, map[string]string{"ping": "pong", "yingling": "yang"})
						By("not copying to any of the destination keys not in the key list for the first secret")
						vaultPathDoesNotContainUnexpectedKeys(expectedPath1, []string{"this"})

						By("copying all the keys in the key list for the second secret")
						vaultPathContainsExpectedKeysAndValues(expectedPath2, map[string]string{"ying": "yang", "lookat": "that"})
						By("not copying to any of the destination keys not in the key list for the second secret")
						vaultPathDoesNotContainUnexpectedKeys(expectedPath2, []string{"ping"})
					})
				})

				When("There is already a key at the destination path", func() {
					BeforeEach(func() {
						_, err := safeSet("/secret/new/place", map[string]string{"hi": "there"})
						Expect(err).NotTo(HaveOccurred())
						paramKeys1 = []interface{}{
							map[string]interface{}{"ying": "yingling"},
						}
						paramKeys2 = []interface{}{
							map[string]interface{}{"this": "lookat"},
						}
						inputSecretMap = append(
							createSecretMaps(src1, dest1, paramKeys1),
							createSecretMaps(src2, dest2, paramKeys2)...,
						)
					})

					It("should merge in secrets and rename them appropriately at the destination without removing existing keys", func() {
						vaultPathContainsExpectedKeysAndValues(expectedPath1, map[string]string{"yingling": "yang", "hi": "there"})
						vaultPathContainsExpectedKeysAndValues(expectedPath2, map[string]string{"lookat": "that"})
					})
				})
			})

			When("An error is expected", func() {
				BeforeEach(func() {
					skipOutErrCheck = true
				})

				Context("Because no source is specified", func() {
					BeforeEach(func() {
						inputSecretMap = createSecretMaps("", "", nil)
					})

					It("should err", func() {
						Expect(outErr).To(HaveOccurred())
					})
				})

				Context("Because Keys contains a key that doesn't exist", func() {
					BeforeEach(func() {
						inputSecretMap = createSecretMaps("/some/place", "",
							[]interface{}{"ping", "king", "ting"},
						)
					})

					It("should err", func() {
						Expect(outErr).To(HaveOccurred())
					})
				})

				Context("Because Keys contains a source key to be renamed that doesn't exist", func() {
					BeforeEach(func() {
						inputSecretMap = createSecretMaps("/some/place", "",
							[]interface{}{
								map[string]interface{}{"ping": "pong"},
								map[string]interface{}{"oops": "dang"},
								map[string]interface{}{"king": "queen"},
							},
						)
					})

					It("should err", func() {
						Expect(outErr).To(HaveOccurred())
					})
				})

				Context("Because Keys contains a map with multiple elements", func() {
					BeforeEach(func() {
						inputSecretMap = createSecretMaps("/some/place", "",
							[]interface{}{
								"ping",
								map[string]interface{}{"ying": "yingling", "oh": "no"},
							},
						)

						It("should err", func() {
							Expect(outErr).To(HaveOccurred())
						})
					})
				})
			})
		})
	})

	AfterEach(func() {
		syscall.Kill(-vault.Process.Pid, syscall.SIGKILL)
		os.RemoveAll(home)
	})
})
