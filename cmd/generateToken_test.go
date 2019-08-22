package cmd

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGenerateTokenNoFlags(t *testing.T) {
	rootCmd.SetArgs([]string{"generateToken"})
	err := rootCmd.Execute()
	assert.Error(t, err)
}

func TestGenerateToken(t *testing.T) {
	rootCmd.SetArgs([]string{"generateToken", "--vault_addr", "https://vault.equityzen.com", "--vault_role", "kemcho_dev", "--kube_token", "/tmp/token", "--vault_write_token", "--vault_token_path", "/tmp/vtok"})
	err := rootCmd.Execute()
	assert.Error(t, err)
}
