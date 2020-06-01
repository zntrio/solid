// Licensed to SolID under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. SolID licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package docker

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"text/template"
	"time"

	"zntr.io/solid/build/mage/git"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

var dockerTemplate = strings.TrimSpace(`
# syntax=docker/dockerfile:experimental

# Arguments
ARG BUILD_DATE
ARG VERSION
ARG VCS_REF

## -------------------------------------------------------------------------------------------------

FROM golang:1.14 as builder

# hadolint ignore=DL3008
RUN set -eux; \
    apt-get update -y && \
    apt-get install -y --no-install-recommends apt-utils bzr upx zip unzip;

{{if .UseBoring }}
# Replace Go with boringssl build.
RUN rm -Rf /usr/local/go && cd /usr/local && curl https://go-boringcrypto.storage.googleapis.com/go1.14.2b4.linux-amd64.tar.gz | tar xz;
{{ end }}

RUN go version

# Create a non-root privilege account to build
RUN adduser --disabled-password --gecos "" -u 1000 golang && \
    mkdir -p "$GOPATH/src/workspace" && \
    chown -R golang:golang "$GOPATH/src/workspace" && \
    mkdir /home/golang/.ssh && \
    mkdir /var/ssh && \
    chown -R golang:golang /home/golang && \
    chown -R golang:golang /var/ssh && \
    chmod 700 /home/golang

# Force go modules
ENV GO111MODULE=on

# Disable go proxy
ENV GOPROXY=direct
ENV GOSUMDB=off

WORKDIR $GOPATH/src/workspace

# Prepare an unprivilegied user for run
RUN set -eux; \
    echo 'nobody:x:65534:65534:nobody:/:' > /tmp/passwd && \
    echo 'nobody:x:65534:' > /tmp/group && \
    mkdir /tmp/.config && \
    chown 65534:65534 /tmp/.config

# Drop privileges to build
USER golang

# Clean go mod cache
RUN set -eux; \
	go clean -modcache

# Checkout mage
RUN set -eux; \
	git clone https://github.com/magefile/mage .mage

# Go to tools
WORKDIR $GOPATH/src/workspace/.mage

# Install mage
RUN go run bootstrap.go

# Back to project root
WORKDIR $GOPATH/src/workspace

# Copy build tools
COPY --chown=golang:golang mage.go .
COPY --chown=golang:golang tools tools/

# Go to tools
WORKDIR $GOPATH/src/workspace/tools

# Install tools
RUN set -eux; \
	mage

# Set path for tools usages
ENV PATH=$GOPATH/src/workspace/tools/bin:$PATH

# Back to project root
WORKDIR $GOPATH/src/workspace

# Copy project go module
COPY --chown=golang:golang . .

# Go to cmd
WORKDIR $GOPATH/src/workspace/cmd/{{.Bin}}

# Build final target
RUN set -eux; \
    mage

# Back to project root
WORKDIR $GOPATH/src/workspace

# Compress binaries
RUN set -eux; \
    upx -9 bin/* && \
    chmod +x bin/*

## -------------------------------------------------------------------------------------------------

# hadolint ignore=DL3007
FROM gcr.io/distroless/static:latest

# Arguments
ARG BUILD_DATE
ARG VERSION
ARG VCS_REF

# Metadata
LABEL \
    org.label-schema.build-date=$BUILD_DATE \
    org.label-schema.name="{{.Name}}" \
    org.label-schema.description="{{.Description}}" \
    org.label-schema.url="{{.URL}}" \
    org.label-schema.vcs-url="https://zntr.io/solid.git" \
    org.label-schema.vcs-ref=$VCS_REF \
    org.label-schema.vendor="go.zenithar.org" \
    org.label-schema.version=$VERSION \
    org.label-schema.schema-version="1.0"

COPY --from=builder /go/src/workspace/bin/{{.Bin}}-linux-amd64 /usr/bin/{{.Bin}}
COPY --from=builder /tmp/group /tmp/passwd /etc/
COPY --from=builder --chown=65534:65534 /tmp/.config /

USER nobody:nobody
WORKDIR /

ENTRYPOINT [ "/usr/bin/{{.Bin}}" ]
CMD ["--help"]
`)

// Command specification for dockerfile generation.
type Command struct {
	Bin         string
	Name        string
	Description string
	URL         string
	UseBoring   bool
}

// Generate Dockerfile for given command.
func Generate(cmd *Command) func() error {
	return func() error {
		buf, err := merge(cmd)
		if err != nil {
			return err
		}

		// Write output to Stdout
		_, errWrite := buf.WriteTo(os.Stdout)
		return errWrite
	}
}

// Build a docker container for given command.
func Build(cmd *Command) func() error {
	return func() error {
		mg.Deps(git.CollectInfo)

		buf, err := merge(cmd)
		if err != nil {
			return err
		}

		// Invoke docker commands
		err = sh.RunWith(
			map[string]string{
				"DOCKER_BUILDKIT": "1",
			},
			"/bin/sh", "-c",
			fmt.Sprintf("echo '%s' | base64 -D | docker build -t cst/%s -f- --build-arg BUILD_DATE=%s --build-arg VERSION=%s --build-arg VCS_REF=%s .", base64.StdEncoding.EncodeToString(buf.Bytes()), cmd.Bin, time.Now().Format(time.RFC3339), git.Tag, git.Revision),
		)

		return err
	}
}

// -----------------------------------------------------------------------------

func merge(cmd *Command) (*bytes.Buffer, error) {
	// Compile template
	dockerFileTmpl, err := template.New("Dockerfile").Parse(dockerTemplate)
	if err != nil {
		return nil, err
	}

	// Merge data
	var buf bytes.Buffer
	if errTmpl := dockerFileTmpl.Execute(&buf, cmd); errTmpl != nil {
		return nil, errTmpl
	}

	// Return buffer without error
	return &buf, nil
}
