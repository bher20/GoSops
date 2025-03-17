package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"go/godecrypter/aes"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	sopsaes "github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/cmd/sops/formats" // Re-export
	"gopkg.in/yaml.v3"
)

type EncryptedFile struct {
	Secrets map[string]string `yaml:"secrets"`
	Sops    struct {
		Kms          []interface{} `yaml:"kms"`
		GcpKms       []interface{} `yaml:"gcp_kms"`
		AzureKv      []interface{} `yaml:"azure_kv"`
		HcVault      []interface{} `yaml:"hc_vault"`
		Age          []interface{} `yaml:"age"`
		Lastmodified time.Time     `yaml:"lastmodified"`
		Mac          string        `yaml:"mac"`
		Pgp          []struct {
			CreatedAt        time.Time `yaml:"created_at"`
			EncryptedDataKey string    `yaml:"enc"`
			Fp               string    `yaml:"fp"`
		} `yaml:"pgp"`
		UnencryptedSuffix string `yaml:"unencrypted_suffix"`
		Version           string `yaml:"version"`
	} `yaml:"sops"`
}

func main() {
	encryptedFile := EncryptedFile{}

	dat, _ := os.ReadFile("/home/ubuntu/development/go/enctest/test.yaml")
	err := yaml.Unmarshal([]byte(dat), &encryptedFile)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	datakey := getDataKey(encryptedFile)
	// cipherClient := aes.NewCipher()

	// pathString := strings.Join([]string{"foo"}, ":") + ":"
	// plaintext, err := cipherClient.Decrypt(encryptedFile.Foo, datakey, pathString)

	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	// fmt.Println(plaintext)

	clear, err := aes.DataWithFormat(dat, formats.Yaml, datakey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(clear))

	// decrypt(encryptedFile, datakey)
}

func decrypt(encryptedFile EncryptedFile, datakey []byte) {
	cipherClient := sopsaes.NewCipher()

	for key, value := range encryptedFile.Secrets {
		if strings.ToLower(key) == "sops" {
			continue
		}

		fmt.Println("Decrypting secret:", key)

		pathString := fmt.Sprintf("secrets:%s:", key)
		plaintext, err := cipherClient.Decrypt(value, datakey, pathString)

		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println(fmt.Sprintf("%v: %v", key, plaintext))
	}
}

func getDataKey(encryptedFile EncryptedFile) []byte {
	privkeyFile, _ := os.ReadFile("/home/ubuntu/development/go/godecrypter/myprivatekeys.asc")
	privateKey, _ := crypto.NewKey(privkeyFile)

	defer privateKey.ClearPrivateParams()

	pgp := crypto.PGP()
	decHandle, err := pgp.
		Decryption().
		DecryptionKey(privateKey).
		New()
	if err != nil {
		fmt.Println(err)
		return nil
	}

	decryptedDataKey, err := decHandle.Decrypt([]byte(encryptedFile.Sops.Pgp[0].EncryptedDataKey), crypto.Armor)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	return decryptedDataKey.Bytes()
}
