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
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/phayes/freeport"
	"github.com/stretchr/testify/assert"
)

////
// Because each test is writing os.args as well as os.out/err these tests can not be run in parallel.
// It is possible to capture and rewrite stdin however this is out of scope for now.
////

// disable TLS for testing
func init() {
	os.Setenv("INTERNAL_TEST", "yes")
}

func TestGenerateTokenNoFlags(t *testing.T) {
	srv, _, ginErr := startGin()
	assert.NoError(t, ginErr, "Gin failed to start for test")

	rootCmd.SetArgs([]string{"generateToken"})
	err := rootCmd.Execute()
	assert.Error(t, err)

	srv.Close()
}

func TestGenerateTokenNoShowToken(t *testing.T) {
	srv, port, ginErr := startGin()
	assert.NoError(t, ginErr, "Gin failed to start for test")
	stdOut := new(bytes.Buffer)
	stdErr := new(bytes.Buffer)

	rootCmd.SetOut(stdOut)
	rootCmd.SetErr(stdErr)
	rootCmd.SetArgs([]string{
		"generateToken",
		"--vault_addr", fmt.Sprintf("http://localhost:%v", port),
		"--vault_role", "kemcho_dev",
		"--kube_token", "this_is_a_fake_token",
		"--vault_path", "kubernetes-good",
	})
	err := rootCmd.Execute()

	assert.NoError(t, err)
	assert.Empty(t, stdErr, "No standard error messages should exist")
	assert.True(t, OutputContainsSubString(stdOut.String(), "redacted"))
	srv.Close()

	t.Log(stdOut.String())
}

func TestGenerateTokenAllOK(t *testing.T) {
	srv, port, ginErr := startGin()
	assert.NoError(t, ginErr, "Gin failed to start for test")
	stdOut := new(bytes.Buffer)
	stdErr := new(bytes.Buffer)

	rootCmd.SetOut(stdOut)
	rootCmd.SetErr(stdErr)
	rootCmd.SetArgs([]string{
		"generateToken",
		"--vault_addr", fmt.Sprintf("http://localhost:%v", port),
		"--vault_role", "kemcho_dev",
		"--kube_token", "this_is_a_fake_token",
		"--vault_path", "kubernetes-good",
		"--show_token",
	})
	err := rootCmd.Execute()

	assert.NoError(t, err)
	assert.Empty(t, stdErr, "No standard error messages should exist")
	assert.True(t, OutputContainsSubString(stdOut.String(), "testtoken"))
	srv.Close()
}

func TestGenerateTokenBadToken(t *testing.T) {
	srv, port, ginErr := startGin()
	assert.NoError(t, ginErr, "Gin failed to start for test")
	stdOut := new(bytes.Buffer)
	stdErr := new(bytes.Buffer)

	rootCmd.SetOut(stdOut)
	rootCmd.SetErr(stdErr)
	rootCmd.SetArgs([]string{
		"generateToken",
		"--vault_addr", fmt.Sprintf("http://localhost:%v", port),
		"--vault_role", "kemcho_dev",
		"--kube_token", "Q:/not.a/valid:path",
		"--vault_path", "kubernetes-good",
		"--show_token",
	})
	err := rootCmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, stdOut, "A standard message should exist")
	assert.True(t, OutputContainsSubString(stdOut.String(), "Invalid token path"), "Desired error message was not found")
	srv.Close()
}

func TestGenerateTokenUnReadableTokenPath(t *testing.T) {
	srv, port, ginErr := startGin()
	assert.NoError(t, ginErr, "Gin failed to start for test")
	stdOut := new(bytes.Buffer)
	stdErr := new(bytes.Buffer)

	rootCmd.SetOut(stdOut)
	rootCmd.SetErr(stdErr)
	rootCmd.SetArgs([]string{
		"generateToken",
		"--vault_addr", fmt.Sprintf("http://localhost:%v", port),
		"--vault_role", "kemcho_dev",
		"--kube_token", "/tmp/",
		"--vault_path", "kubernetes-good",
		"--show_token",
	})
	err := rootCmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, stdOut, "A standard message should exist")
	assert.True(t, OutputContainsSubString(stdOut.String(), "Failed to read kube_token path"), "Desired error message was not found")
	srv.Close()
}

func TestGenerateTokenValidTokenPath(t *testing.T) {
	srv, port, ginErr := startGin()
	assert.NoError(t, ginErr, "Gin failed to start for test")
	stdOut := new(bytes.Buffer)
	stdErr := new(bytes.Buffer)

	file, fileErr := ioutil.TempFile("/tmp/", "token-*")
	assert.NoError(t, fileErr)

	rootCmd.SetOut(stdOut)
	rootCmd.SetErr(stdErr)
	rootCmd.SetArgs([]string{
		"generateToken",
		"--vault_addr", fmt.Sprintf("http://localhost:%v", port),
		"--vault_role", "kemcho_dev",
		"--kube_token", file.Name(),
		"--vault_path", "kubernetes-good",
		"--show_token",
	})
	err := rootCmd.Execute()
	assert.NoError(t, err)
	assert.Empty(t, stdErr, "No standard error messages should exist")
	assert.True(t, OutputContainsSubString(stdOut.String(), "testtoken"))
	defer os.Remove(file.Name())
	srv.Close()
}

func TestGenerateTokenRequestFail(t *testing.T) {
	srv, port, ginErr := startGin()
	assert.NoError(t, ginErr, "Gin failed to start for test")
	stdOut := new(bytes.Buffer)
	stdErr := new(bytes.Buffer)

	rootCmd.SetOut(stdOut)
	rootCmd.SetErr(stdErr)
	rootCmd.SetArgs([]string{
		"generateToken",
		"--vault_addr", fmt.Sprintf("http://localhost:%v", port),
		"--vault_role", "kemcho_dev",
		"--kube_token", "fake_token",
		"--vault_path", "kubernetes-timeout",
		"--vault_timeout", "5",
		"--show_token",
	})
	err := rootCmd.Execute()
	assert.NoError(t, err)
	assert.True(t, OutputContainsSubString(stdOut.String(), "request canceled"), "Desired error message was not found")
	srv.Close()
}

func TestGenerateTokenBadResponse(t *testing.T) {
	srv, port, ginErr := startGin()
	assert.NoError(t, ginErr, "Gin failed to start for test")
	stdOut := new(bytes.Buffer)
	stdErr := new(bytes.Buffer)

	rootCmd.SetOut(stdOut)
	rootCmd.SetErr(stdErr)
	rootCmd.SetArgs([]string{
		"generateToken",
		"--vault_addr", fmt.Sprintf("http://localhost:%v", port),
		"--vault_role", "kemcho_dev",
		"--kube_token", "fake_token",
		"--vault_path", "kubernetes-non200",
		"--show_token",
	})
	err := rootCmd.Execute()
	assert.NoError(t, err)
	assert.True(t, OutputContainsSubString(stdOut.String(), "Non-200 respond code"), "Desired error message was not found")
	srv.Close()
}

func TestGenerateTokenMissingToken(t *testing.T) {
	srv, port, ginErr := startGin()
	assert.NoError(t, ginErr, "Gin failed to start for test")
	stdOut := new(bytes.Buffer)
	stdErr := new(bytes.Buffer)

	rootCmd.SetOut(stdOut)
	rootCmd.SetErr(stdErr)
	rootCmd.SetArgs([]string{
		"generateToken",
		"--vault_addr", fmt.Sprintf("http://localhost:%v", port),
		"--vault_role", "kemcho_dev",
		"--kube_token", "fake_token",
		"--vault_path", "kubernetes-notoken",
		"--show_token",
	})
	err := rootCmd.Execute()
	assert.NoError(t, err)
	assert.True(t, OutputContainsSubString(stdErr.String(), "No token received from vault"), "Desired error message was not found")
	srv.Close()
}

func TestGenerateTokenWriteFail(t *testing.T) {
	srv, port, ginErr := startGin()
	assert.NoError(t, ginErr, "Gin failed to start for test")
	stdOut := new(bytes.Buffer)
	stdErr := new(bytes.Buffer)

	rootCmd.SetOut(stdOut)
	rootCmd.SetErr(stdErr)
	rootCmd.SetArgs([]string{
		"generateToken",
		"--vault_addr", fmt.Sprintf("http://localhost:%v", port),
		"--vault_role", "kemcho_dev",
		"--kube_token", "this_is_a_fake_token",
		"--vault_path", "kubernetes-good",
		"--show_token",
		"--vault_write_token",
		"--vault_token_path", "/does_not_exist/token",
	})
	err := rootCmd.Execute()

	assert.NoError(t, err)
	assert.Empty(t, stdErr, "No standard error messages should exist")
	assert.True(t, OutputContainsSubString(stdOut.String(), "Failed to write vault token"), "Desired error message was not found")
	srv.Close()
}

func TestGenerateTokenWriteOK(t *testing.T) {
	srv, port, ginErr := startGin()
	assert.NoError(t, ginErr, "Gin failed to start for test")
	stdOut := new(bytes.Buffer)
	stdErr := new(bytes.Buffer)

	file, fileErr := ioutil.TempFile("/tmp/", "token-*")
	assert.NoError(t, fileErr)

	rootCmd.SetOut(stdOut)
	rootCmd.SetErr(stdErr)
	rootCmd.SetArgs([]string{
		"generateToken",
		"--vault_addr", fmt.Sprintf("http://localhost:%v", port),
		"--vault_role", "kemcho_dev",
		"--kube_token", "this_is_a_fake_token",
		"--vault_path", "kubernetes-good",
		"--show_token",
		"--vault_write_token",
		"--vault_token_path", file.Name(),
	})
	err := rootCmd.Execute()

	assert.NoError(t, err)
	assert.Empty(t, stdErr, "No standard error messages should exist")
	assert.True(t, OutputContainsSubString(stdOut.String(), "Vault token successfully generated"), "Desired message was not found")

	tokenData, err := ioutil.ReadFile(file.Name())
	assert.NoError(t, err, "Failed to read temp file in for verification")
	assert.Equal(t, "testtoken", string(tokenData), "Invalid token saved to test file")

	defer os.Remove(file.Name())
	srv.Close()
}

func TestRenewTokenBadToken(t *testing.T) {
	stdOut := new(bytes.Buffer)
	stdErr := new(bytes.Buffer)

	rootCmd.SetOut(stdOut)
	rootCmd.SetErr(stdErr)
	rootCmd.SetArgs([]string{
		"renewToken",
		"--vault_addr", fmt.Sprintf("http://localhost:%v", 0),
		"--vault_timeout", "5",
		"--vault_lease_ttl", "10",
		"--vault_token", "Q:/not.a/valid:path",
	})
	err := rootCmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, stdOut, "A standard message should exist")
	assert.True(t, OutputContainsSubString(stdOut.String(), "Invalid token path"), "Desired error message was not found")
}

func TestRenewTokenUnReadableTokenPath(t *testing.T) {
	stdOut := new(bytes.Buffer)
	stdErr := new(bytes.Buffer)

	rootCmd.SetOut(stdOut)
	rootCmd.SetErr(stdErr)
	rootCmd.SetArgs([]string{
		"renewToken",
		"--vault_addr", fmt.Sprintf("http://localhost:%v", 0),
		"--vault_timeout", "5",
		"--vault_lease_ttl", "10",
		"--vault_token", "/tmp/",
	})
	err := rootCmd.Execute()

	t.Log(stdOut.String())

	assert.NoError(t, err)
	assert.NotEmpty(t, stdOut, "A standard message should exist")
	assert.True(t, OutputContainsSubString(stdOut.String(), "Failed to read vault_token path"), "Desired error message was not found")

}

func TestRenewTokenEmptyToken(t *testing.T) {
	stdOut := new(bytes.Buffer)
	stdErr := new(bytes.Buffer)

	rootCmd.SetOut(stdOut)
	rootCmd.SetErr(stdErr)
	rootCmd.SetArgs([]string{
		"renewToken",
		"--vault_addr", fmt.Sprintf("http://localhost:%v", 0),
		"--vault_timeout", "5",
		"--vault_lease_ttl", "10",
		"--vault_token", "",
	})
	err := rootCmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, stdOut, "A standard message should exist")
	assert.True(t, OutputContainsSubString(stdOut.String(), "No token found"), "Desired error message was not found")

}

func TestRenewTokenAllOk(t *testing.T) {
	srv, port, ginErr := startGin()
	assert.NoError(t, ginErr, "Gin failed to start for test")
	stdOut := new(bytes.Buffer)
	stdErr := new(bytes.Buffer)

	rootCmd.SetOut(stdOut)
	rootCmd.SetErr(stdErr)
	rootCmd.SetArgs([]string{
		"renewToken",
		"--vault_addr", fmt.Sprintf("http://localhost:%v", port),
		"--vault_lease_ttl", "10",
		"--vault_token", "token-good",
	})

	// delay in routine to cancel loop
	go func() {
		time.Sleep(10 * time.Second)
		testCancel()
	}()
	err := rootCmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, stdOut, "A standard message should exist")
	assert.True(t, OutputContainsSubString(stdOut.String(), "Token renewed"), "Desired stdout message was not found")

	srv.Close()
}

func TestRenewTokenTimeout(t *testing.T) {
	srv, port, ginErr := startGin()
	assert.NoError(t, ginErr, "Gin failed to start for test")
	stdOut := new(bytes.Buffer)
	stdErr := new(bytes.Buffer)

	rootCmd.SetOut(stdOut)
	rootCmd.SetErr(stdErr)
	rootCmd.SetArgs([]string{
		"renewToken",
		"--vault_addr", fmt.Sprintf("http://localhost:%v", port),
		"--vault_timeout", "5",
		"--vault_lease_ttl", "10",
		"--vault_token", "token-timeout",
	})

	// delay in routine to cancel loop
	go func() {
		time.Sleep(10 * time.Second)
		testCancel()
	}()
	err := rootCmd.Execute()

	t.Log(stdOut.String())
	t.Log(stdErr.String())
	assert.NoError(t, err)
	assert.NotEmpty(t, stdOut, "A standard message should exist")
	assert.True(t, OutputContainsSubString(stdOut.String(), "Failed while making vault token renewal request"), "Desired error message was not found")

	srv.Close()
}

func TestRenewTokenFail(t *testing.T) {
	srv, port, ginErr := startGin()
	assert.NoError(t, ginErr, "Gin failed to start for test")
	stdOut := new(bytes.Buffer)
	stdErr := new(bytes.Buffer)

	rootCmd.SetOut(stdOut)
	rootCmd.SetErr(stdErr)
	rootCmd.SetArgs([]string{
		"renewToken",
		"--vault_addr", fmt.Sprintf("http://localhost:%v", port),
		"--vault_lease_ttl", "10",
		"--vault_token", "token-bad",
	})

	err := rootCmd.Execute()
	time.Sleep(8 * time.Second)
	assert.NoError(t, err)
	assert.NotEmpty(t, stdOut, "A standard message should exist")
	assert.True(t, OutputContainsSubString(stdOut.String(), "Failed to renew vault token"), "Desired error message was not found")

	srv.Close()
}

func TestRenewTokenSoftFail(t *testing.T) {
	srv, port, ginErr := startGin()
	assert.NoError(t, ginErr, "Gin failed to start for test")
	stdOut := new(bytes.Buffer)
	stdErr := new(bytes.Buffer)

	rootCmd.SetOut(stdOut)
	rootCmd.SetErr(stdErr)
	rootCmd.SetArgs([]string{
		"renewToken",
		"--vault_addr", fmt.Sprintf("http://localhost:%v", port),
		"--vault_lease_ttl", "10",
		"--vault_token", "token-bad",
		"--soft_fail",
	})

	// delay in routine to cancel loop
	go func() {
		time.Sleep(10 * time.Second)
		testCancel()
	}()
	err := rootCmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, stdOut, "A standard message should exist")
	assert.True(t, OutputContainsSubString(stdOut.String(), "Failed to renew vault token"), "Desired error message was not found")

	srv.Close()
}

////// Test utilities

type Path struct {
	Path string `uri:"path" binding:"required" validate:"string"`
}

// Start a gin/http router on a random port for faking vault responses
func startGin() (*http.Server, string, error) {
	port, err := freeport.GetFreePort()
	if err != nil {
		return nil, "0", err
	}

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())
	r.POST("/v1/auth/:path/login", fakeLogin)
	r.POST("/v1/auth/:path/renew-self", fakeRenewal)
	srv := &http.Server{
		Addr:    "localhost:" + strconv.Itoa(port),
		Handler: r,
	}
	go srv.ListenAndServe()
	return srv, strconv.Itoa(port), nil
}

// return a faked login response based on content
func fakeLogin(c *gin.Context) {
	var Path Path

	if err := c.ShouldBindUri(&Path); err != nil {
		c.JSONP(http.StatusBadRequest, Errors{Errors: []string{"missing client token"}})
		return
	}

	switch {
	case Path.Path == "kubernetes-good":
		token := Token{
			Auth: Auth{
				Renewable:     true,
				LeaseDuration: 600,
				ClientToken:   "testtoken",
			},
		}
		c.JSON(http.StatusOK, token)
		return

	case Path.Path == "kubernetes-timeout":
		// artificial delay to trigger resty timeout
		time.Sleep(7 * time.Second)
		return

	case Path.Path == "kubernetes-non200":
		c.JSONP(http.StatusBadRequest, Errors{Errors: []string{"missing client token"}})
		return

	case Path.Path == "kubernetes-notoken":
		token := Token{
			Auth: Auth{
				Renewable:     true,
				LeaseDuration: 600,
			},
		}
		c.JSON(http.StatusOK, token)
		return
	}

	// catch-all missing
	if err := c.ShouldBindUri(&Path); err != nil {
		c.JSONP(http.StatusBadRequest, Errors{Errors: []string{"missing client token"}})
		return
	}
}

// return a faked renewal response
func fakeRenewal(c *gin.Context) {
	vaultToken := c.Request.Header.Get("X-Vault-Token")

	switch {
	case vaultToken == "token-good":
		c.JSON(http.StatusOK, nil)
		return

	case vaultToken == "token-timeout":
		time.Sleep(7 * time.Second)
		c.JSON(http.StatusOK, nil)
		return
	}

	// catch-all missing
	c.JSON(http.StatusInternalServerError, nil)
}

// given a string out/err buffer look for a string in output line by line
func OutputContainsSubString(out string, s string) bool {
	for _, value := range strings.Split(out, "\n") {
		if strings.Contains(value, s) {
			return true
		}
	}
	return false
}
