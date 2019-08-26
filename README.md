# vault-k8s-utils - Vault Kubernetes Utilities
<p align="center">
<p align="center">
<a href="https://circleci.com/gh/EquityZen/vault-k8s-utils"><img src="https://circleci.com/gh/EquityZen/vault-k8s-utils.svg?style=svg" alt="Build Status"></a>
<a href="https://codecov.io/gh/EquityZen/vault-k8s-utils/branch/master"><img src="https://codecov.io/gh/EquityZen/vault-k8s-utils/branch/master/graph/badge.svg" alt="Code Coverage"></a>
<a href="https://goreportcard.com/report/EquityZen/vault-k8s-utils"><img src="https://goreportcard.com/badge/github.com/EquityZen/vault-k8s-utils" alt="Go Report Card"></a>
<a href="https://github.com/EquityZen/vault-k8s-utils/releases/latest"><img src="https://img.shields.io/github/v/tag/EquityZen/vault-k8s-utils?sort=semver" alt="Release Version"></a>
<a href="LICENSE"><img src="https://img.shields.io/github/license/EquityZen/vault-k8s-utils" alt="License"></a></p>
</p>

## What is vault-k8s-utils
vault-k8s-utils is a small simple Go application to handle the generation and renewal of Vault tokens within a Kubernetes cluster.  This utility is intended to be used as a initContainer or sidecar to enable vault operations from within a pod.

## Features
  * Vault token generation.
  * Vault token renewal.

## Requirements
  * Kubernetes 1.10+
  * HashiCorp Vault 1.0.0+

## Usage

### Token generation
By default a token will be generated but not output to stdout for security reasons.  The generated token can be either displayed with `--show_token` or written to a file with `--vault_token_path /tmp/token` and `--vault_write_token`.
```
vault-k8s-utils generateToken --vault_addr https://your.vault.com --kube_token a_valid_token --vault_role your_role_name
Vault token successfully generated
Token: <redacted>
Renewable: true
Lease Duration: 86400s
```
With Token Output:
```
vault-k8s-utils generateToken --vault_addr https://your.vault.com --kube_token a_valid_token --vault_role your_role_name --show_token
Vault token successfully generated
Token: s.notarealtoken
Renewable: true
Lease Duration: 86400s
```
Output To File:
```
vault-k8s-utils generateToken --vault_addr https://your.vault.com --kube_token a_valid_token --vault_role your_role_name --vault_write_token --vault_token_path /tmp/tmptoken
Vault token successfully generated
Token: <redacted>
Renewable: true
Lease Duration: 86400s

cat /tmp/tmptoken 
s.notarealtoken
```

### Token Renewal
Using the token renewal command starts a timed loop that will continue to renew the token until exited or a error occurs.  The is also possible to fail softly (not exit) with the `--soft_fail` option.  This is indented to be used as a sidecar in a pod that needs a constantly valid Vault token.
```
vault-k8s-utils renewToken --vault_addr https://your.vault.com --vault_lease_ttl 5 --vault_token /tmp/tmptoken 
Token renewed
Token renewed
< forever >
```

## Kubernetes Usage
Comming soon!

## Contribution or Bugs
We welcome any contributions or bug reports!

## License
vault-k8s-utils is licenses under Apache 2.0, refer to the [LICENSE](LICENSE) file.