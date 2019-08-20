/*
Copyright © 2019 NAME HERE <EMAIL ADDRESS>

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
	"os"
	"strings"

	"github.com/go-resty/resty/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type Errors struct {
	Errors []string `json:"errors"`
}

type Token struct {
	RequestID     string      `json:"request_id"`
	LeaseID       string      `json:"lease_id"`
	Renewable     bool        `json:"renewable"`
	LeaseDuration int         `json:"lease_duration"`
	Data          interface{} `json:"data"`
	WrapInfo      interface{} `json:"wrap_info"`
	Warnings      interface{} `json:"warnings"`
	Auth          struct {
		ClientToken   string   `json:"client_token"`
		Accessor      string   `json:"accessor"`
		Policies      []string `json:"policies"`
		TokenPolicies []string `json:"token_policies"`
		Metadata      struct {
			Role                     string `json:"role"`
			ServiceAccountName       string `json:"service_account_name"`
			ServiceAccountNamespace  string `json:"service_account_namespace"`
			ServiceAccountSecretName string `json:"service_account_secret_name"`
			ServiceAccountUID        string `json:"service_account_uid"`
		} `json:"metadata"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
		EntityID      string `json:"entity_id"`
		TokenType     string `json:"token_type"`
		Orphan        bool   `json:"orphan"`
	} `json:"auth"`
}

var showToken bool

// generateTokenCmd represents the generateToken command
var generateTokenCmd = &cobra.Command{
	Use:   "generateToken",
	Short: "Given a K8S token authenticate with vault and generate a token",
	Long: `Using a valid JWT from kubernetes generate a vault token and store it to the specified file path.

This command assumes a valid K8S authentication method is setup in Vault.`,
	Run: func(cmd *cobra.Command, args []string) {
		// get kube token if path not value
		kToken, _ := cmd.Flags().GetString("kube_token")
		if _, err := os.Stat(kToken); err == nil {
			// value is a path to file, read in file and store as kToken
			fData, err := ioutil.ReadFile(kToken)
			if err != nil {
				fmt.Printf("failed to read kube_token path (%v), err: %v\n", kToken, err)
				os.Exit(1)
			}
			kToken = string(fData)
		}

		if strings.Contains(kToken, ":") || strings.Contains(kToken, "/") {
			fmt.Printf("Invalid token path or format: %v\n", kToken)
			os.Exit(1)
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
			fmt.Printf("Failed while making vault login request: %v", err)
			os.Exit(1)
		}

		// Ensure 200 response code
		if resp.StatusCode() != 200 {
			fmt.Printf("Non-200 respond code: %v, errs %v\n", resp.Status(), Errors.Errors)
			os.Exit(1)
		}

		fmt.Println("Vault token sucessfully generated")
		if showToken {
			fmt.Printf("Token: %v\n", Token.Auth.ClientToken)
		} else {
			fmt.Println("Token: <redacted>")
		}
		fmt.Printf("Renewable: %v\n", Token.Auth.Renewable)
		fmt.Printf("Lease Duration: %vs\n", Token.Auth.LeaseDuration)
	},
}

func init() {
	rootCmd.AddCommand(generateTokenCmd)
	generateTokenCmd.Flags().StringP("kube_token", "", viper.GetString("KUBE_TOKEN"), "Kubernetes service account token or path to token")
	generateTokenCmd.Flags().StringP("vault_role", "", viper.GetString("VAULT_ROLE"), "Name of the associated vault role to generate the token under.")
	generateTokenCmd.Flags().StringP("vault_path", "", viper.GetString("VAULT_PATH"), "Name of the vault auth method path for kubernetes (kubernetes).")
	generateTokenCmd.Flags().BoolVarP(&showToken, "show_token", "", viper.GetBool("SHOW_TOKEN"), "Output vault token to screen. SECURITY RISK!")
	_ = generateTokenCmd.MarkFlagRequired("kube_token")
	_ = generateTokenCmd.MarkFlagRequired("vault_role")
}