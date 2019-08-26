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

## Downloads
Available via the release page or [Dockerhub](https://hub.docker.com/r/equityzen/vault-k8s-utils)

## Kubernetes Usage
To use this tool as part of a kubernetes pod deployment just add the following to your pod definitions.  This will write the vault token to the path specified `/etc/vault/token` which can then be used by your pod.  For example it can be used with [envconsul](https://github.com/hashicorp/envconsul) for dynamic environment variables.
```yaml
< before containers >
      initContainers:
      - command:
        - sh
        - -c
        - vault-k8s-utils generateToken --vault_addr https://your.vault.com --kube_token
          /var/run/secrets/kubernetes.io/serviceaccount/token --vault_role your_role_name
          --vault_write_token --vault_token_path /etc/vault/token
        image: equityzen/vault-k8s-utils
        imagePullPolicy: Always
        name: init-vault
        resources:
          limits:
            memory: 50Mi
          requests:
            memory: 50Mi
        volumeMounts:
        - mountPath: /etc/vault
          name: vault-token
< within containers >
      containers:
      - command:
        - sh
        - -c
        - vault-k8s-utils renewToken --vault_addr https://your.vault.com --vault_token
          /etc/vault/token --vault_lease_ttl 3600
        image: equityzen/vault-k8s-utils
        imagePullPolicy: Always
        lifecycle:
          preStop:
            exec:
              command:
              - sh
              - -c
              - |
                export VAULT_TOKEN=$(cat /etc/vault/token); curl --insecure --request POST --header "X-Vault-Token: $VAULT_TOKEN" https://your.vault.com/v1/auth/token/revoke-self;
        name: vault-manager
        resources:
          limits:
            memory: 50Mi
          requests:
            memory: 50Mi
        volumeMounts:
        - mountPath: /etc/vault
          name: vault-token
      volumes:
      - emptyDir: {}
        name: vault-token
```
The above example assumes you will mount a emptyDir to /etc/vault but this can be any path shared between the pod containers.  For the moment token revocation is not included in the utilities.  This will be coming in a future version.


## Contribution or Bugs
We welcome any contributions or bug reports!

## License
vault-k8s-utils is licenses under Apache 2.0, refer to the [LICENSE](LICENSE) file.