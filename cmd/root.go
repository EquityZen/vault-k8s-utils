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
	"os"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var vaultAddr string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "vault-k8s-utils",
	Short: "A small helper tool for using Hashicorp Vault within Kubernetes",
	Long: `vault-k8s-utils is a small helper tool for using HashiCorp Vault within Kubernetes.

Use this tool for generating and manipulating vault tokens via K8S pod sidecars`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.vault-k8s-utils.yaml)")
	rootCmd.PersistentFlags().StringVar(&vaultAddr, "vault_addr", viper.GetString("VAULT_ADDR"), "Base URI to Vault API (https://www.your-vault.com)")
	_ = rootCmd.MarkPersistentFlagRequired("vault_addr")

	rootCmd.Version = "0.0.1"
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".vault-k8s-utils" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".vault-k8s-utils")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}

	viper.SetDefault("VAULT_PATH", "kubernetes")
	viper.SetDefault("SHOW_TOKEN", false)
	viper.SetDefault("VAULT_TOKEN_PATH", "/etc/vault/token")
	viper.SetDefault("VAULT_LEASE_TLL", 3600)
}
