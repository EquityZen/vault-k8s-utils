/*
Copyright © 2019 EquityZen, Inc. <technology@equityzen.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/go-resty/resty/v2"
	"github.com/spf13/cobra"
)

var showToken bool
var vaultTokenPath string
var vaultWriteToken bool

// generateTokenCmd represents the generateToken command
var generateTokenCmd = &cobra.Command{
	Use:   "generateToken",
	Short: "Given a K8S token authenticate with vault and generate a token",
	Long: `Using a valid JWT from kubernetes generate a vault token and store it to the specified file path.

This command assumes a valid K8S authentication method is setup in Vault.`,
	Run: GenerateToken,
}

func init() {
	rootCmd.AddCommand(generateTokenCmd)
	generateTokenCmd.Flags().StringP("kube_token", "", "", "Kubernetes service account token or path to token")
	generateTokenCmd.Flags().StringP("vault_role", "", "", "Name of the associated vault role to generate the token under.")
	generateTokenCmd.Flags().StringP("vault_path", "", "kubernetes", "Name of the vault auth method path for kubernetes (kubernetes).")
	generateTokenCmd.Flags().BoolVarP(&showToken, "show_token", "", false, "Output vault token to screen. SECURITY RISK!")
	generateTokenCmd.Flags().BoolVarP(&vaultWriteToken, "vault_write_token", "", false, "Write vault token to file, use with vault_token_path option")
	generateTokenCmd.Flags().StringVarP(&vaultTokenPath, "vault_token_path", "", "etc/vault/token", "Path to write out vault token to (/etc/vault/token)")
	_ = generateTokenCmd.MarkFlagRequired("kube_token")
	_ = generateTokenCmd.MarkFlagRequired("vault_role")
}

func GenerateToken(cmd *cobra.Command, args []string) {
	// get kube token if path not value
	kToken, _ := cmd.Flags().GetString("kube_token")
	if _, err := os.Stat(kToken); err == nil {
		// value is a path to file, read in file and store as kToken
		fData, err := ioutil.ReadFile(kToken)
		if err != nil {
			log.Fatalf("failed to read kube_token path (%v), err: %v\n", kToken, err)
		}
		kToken = string(fData)
	}

	if strings.Contains(kToken, ":") || strings.Contains(kToken, "/") {
		log.Fatalf("Invalid token path or format: %v\n", kToken)
	}

	// get vault role/path
	vRole, _ := cmd.Flags().GetString("vault_role")
	vPath, _ := cmd.Flags().GetString("vault_path")

	var Errors Errors
	var Token Token

	// Make request to vault API
	client := resty.New()
	resp, err := client.R().
		SetBody(map[string]interface{}{"jwt": kToken, "role": vRole}).
		SetError(&Errors).
		SetResult(&Token).
		Post(fmt.Sprintf("%v/v1/auth/%v/login", vaultAddr, vPath))
	if err != nil {
		log.Fatalf("Failed while making vault login request: %v", err)
	}

	// Ensure 200 response code
	if resp.StatusCode() != 200 {
		log.Fatalf("Non-200 respond code: %v, errs %v\n", resp.Status(), Errors.Errors)
	}

	// Print out token info
	log.Println("Vault token successfully generated")
	if showToken {
		log.Printf("Token: %v\n", Token.Auth.ClientToken)
	} else {
		log.Println("Token: <redacted>")
	}
	log.Printf("Renewable: %v\n", Token.Auth.Renewable)
	log.Printf("Lease Duration: %vs\n", Token.Auth.LeaseDuration)

	// Write token to filesystem
	if vaultWriteToken {
		err := ioutil.WriteFile(vaultTokenPath, []byte(Token.Auth.ClientToken), 0666)
		if err != nil {
			log.Fatalf("Failed to write vault token to file: %v", err)
		}
	}
}
