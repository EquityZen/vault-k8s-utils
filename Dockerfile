#
# Stage 1 - Compile and compress code
#

FROM golang:1.12-alpine as builder

# Install XZ and UPZ
RUN apk update && apk add ca-certificates xz upx git && rm -rf /var/cache/apk/* \
    && rm -rf /var/lib/apt/lists/*

ARG gh_token
RUN echo "machine github.com login ezbuildbot password $gh_token" >> ~/.netrc
ARG git_hash=""

# Create work dir
WORKDIR /go/src/github.com/EquityZen/vault-k8s-utils

# copy entire directory
COPY . .

# Build app
RUN GO111MODULE=on CGO_ENABLED=0 GOOS=linux go build -ldflags "-X main.GitVersion=$git_hash" -a -installsuffix cgo -o vault-k8s-utils github.com/EquityZen/vault-k8s-utils

# strip and compress the binary
RUN upx vault-k8s-utils

#
# Stage 2 -  Add complied binary to new clean container
#
FROM alpine

# add ca-certificates
RUN apk update \
  && apk add ca-certificates

# copy the binary from builder
COPY --from=builder /go/src/github.com/EquityZen/vault-k8s-utils/vault-k8s-utils /usr/local/bin/vault-k8s-utils


# run the binary
CMD ["./usr/local/bin/vault-k8s-utils"]