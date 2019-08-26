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
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/spf13/cobra"
)

var vaultToken string
var vaultLeaseTTL int
var softFail bool
var testContext, testCancel = context.WithCancel(context.Background())

// renewTokenCmd represents the renewToken command
var renewTokenCmd = &cobra.Command{
	Use:   "renewToken",
	Short: "Given a valid Vault token attempt to renew token with vault API",
	Long: `Using a previously generated Vault token attempt to renew to extend the life of the token.

The renewal time is should be the full length of the token TTL, renewal will happen at the half-way point.`,
	Run: RenewToken,
}

func init() {
	rootCmd.AddCommand(renewTokenCmd)
	renewTokenCmd.Flags().StringVarP(&vaultToken, "vault_token", "", "/etc/vault/token", "Vault token or path to token (/etc/vault/token)")
	renewTokenCmd.Flags().IntVarP(&vaultLeaseTTL, "vault_lease_ttl", "", 3600, "Token time to live in seconds (3600)")
	renewTokenCmd.Flags().BoolVarP(&softFail, "soft_fail", "", false, "Do not exit on renewal failure (false)")
}

func RenewToken(cmd *cobra.Command, args []string) {
	testContext, testCancel = context.WithCancel(context.Background())
	// Get token directly or from path
	if _, err := os.Stat(vaultToken); err == nil {
		// value is a path to file, read in file and store as kToken
		fData, err := ioutil.ReadFile(vaultToken)
		if err != nil {
			cmd.PrintErrf("Failed to read vault_token path (%v), err: %v\n", vaultToken, err)
			ExitHook()
			return
		}
		vaultToken = string(fData)
	}

	if strings.Contains(vaultToken, ":") || strings.Contains(vaultToken, "/") {
		cmd.PrintErrf("Invalid token path or format: %v\n", vaultToken)
		ExitHook()
		return
	}

	if len(vaultToken) == 0 {
		cmd.PrintErrln("No token found, please specify one")
		ExitHook()
		return
	}

	var Errors Errors

	// We renew half-way into the lease
	leaseTimer := time.NewTicker(time.Duration(vaultLeaseTTL/2) * time.Second).C
timer:
	for {
		select {
		case <-leaseTimer:
			client := resty.New()
			client.SetTimeout(time.Duration(httpTimeout) * time.Second)
			resp, err := client.R().
				SetHeader("X-Vault-Token", vaultToken).
				SetError(&Errors).
				Post(fmt.Sprintf("%v/v1/auth/token/renew-self", vaultAddr))
			if err != nil {
				cmd.PrintErrf("Failed while making vault token renewal request: %v\n", err)
				ExitHook()
				return
			}

			if resp.StatusCode() != 200 {
				if !softFail {
					cmd.PrintErrf("Failed to renew vault token: %v\n", Errors.Errors)
					ExitHook()
					return
				}
				cmd.Printf("Failed to renew vault token: %v\n", Errors.Errors)
			} else {
				cmd.Println("Token renewed")
			}
		case <-testContext.Done():
			// Break for testing
			break timer
		}
	}
}
