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
	"log"
	"os"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var vaultToken string
var vaultLeaseTTL int
var softFail bool

// renewTokenCmd represents the renewToken command
var renewTokenCmd = &cobra.Command{
	Use:   "renewToken",
	Short: "Given a valid Vault token attempt to renew token with vault API",
	Long: `Using a previously generated Vault token attempt to renew to extend the life of the token.

The renewal time is should be the full length of the token TTL, renewal will happen at the half-way point.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Get token directly or from path
		if _, err := os.Stat(vaultToken); err == nil {
			// value is a path to file, read in file and store as kToken
			fData, err := ioutil.ReadFile(vaultToken)
			if err != nil {
				log.Fatalf("failed to read vault_token path (%v), err: %v\n", vaultToken, err)
			}
			vaultToken = string(fData)
		}

		if strings.Contains(vaultToken, ":") || strings.Contains(vaultToken, "/") {
			log.Fatalf("Invalid token path or format: %v\n", vaultToken)
		}

		if len(vaultToken) == 0 {
			log.Fatalln("No token found, please specify one")
		}

		var Errors Errors

		// We renew half-way into the lease
		leaseTimer := time.NewTicker(time.Duration(vaultLeaseTTL/2) * time.Second).C
		for {
			select {
			case <-leaseTimer:
				client := resty.New()
				resp, err := client.R().
					SetHeader("X-Vault-Token", vaultToken).
					SetError(&Errors).
					Post(fmt.Sprintf("%v/v1/auth/token/renew-self", vaultAddr))
				if err != nil {
					log.Fatalf("Failed while making vault token renewal request: %v", err)
				}

				if resp.StatusCode() != 200 {
					if !softFail {
						log.Fatalf("Failed to rewnew vault token: %v", Errors.Errors)
					}
					log.Printf("Failed to rewnew vault token: %v", Errors.Errors)
				} else {
					log.Printf("Token renewed")
				}
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(renewTokenCmd)
	renewTokenCmd.Flags().StringVarP(&vaultToken, "vault_token", "", viper.GetString("VAULT_TOKEN_PATH"), "Vault token or path to token (/etc/vault/token)")
	renewTokenCmd.Flags().IntVarP(&vaultLeaseTTL, "vault_lease_ttl", "", viper.GetInt("VAULT_LEASE_TLL"), "Token time to live in seconds (3600)")
	renewTokenCmd.Flags().BoolVarP(&softFail, "soft_fail", "", viper.GetBool("VAULT_SOFT_FAIL"), "Do not exit on renewal failure (false)")
}
