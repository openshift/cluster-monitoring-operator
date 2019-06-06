SHELL=/bin/bash -o pipefail

GO_PKG=github.com/openshift/cluster-monitoring-operator
REPO?=quay.io/openshift/cluster-monitoring-operator
TAG?=$(shell git rev-parse --short HEAD)
VERSION=$(shell cat VERSION | tr -d " \t\n\r")

PKGS=$(shell go list ./... | grep -v -E '/vendor/|/test|/examples')
GOLANG_FILES:=$(shell find . -name \*.go -print) pkg/manifests/bindata.go
FIRST_GOPATH:=$(firstword $(subst :, ,$(shell go env GOPATH)))
EMBEDMD_BIN=$(FIRST_GOPATH)/bin/embedmd
GOBINDATA_BIN=$(FIRST_GOPATH)/bin/go-bindata
JB_BINARY=$(FIRST_GOPATH)/bin/jb
GOJSONTOYAML_BINARY=$(FIRST_GOPATH)/bin/gojsontoyaml
ASSETS=$(shell grep -oh 'assets/.*\.yaml' pkg/manifests/manifests.go)
JSONNET_SRC=$(shell find ./jsonnet -type f)
JSONNET_VENDOR=jsonnet/jsonnetfile.lock.json jsonnet/vendor

GO_BUILD_RECIPE=GOOS=linux CGO_ENABLED=0 go build --ldflags="-s -X $(GO_PKG)/pkg/operator.Version=$(VERSION)"
CONTAINER_CMD:=docker run --rm \
		-u="$(shell id -u):$(shell id -g)" \
		-v "$(shell go env GOCACHE):/.cache/go-build" \
		-v "$(PWD):/go/src/$(GO_PKG):Z" \
		-w "/go/src/$(GO_PKG)" \
		-e GO111MODULE=on \
		quay.io/coreos/jsonnet-ci

.PHONY: all
all: format generate build test

.PHONY: clean
clean:
	# Remove all files and directories ignored by git.
	git clean -Xfd .

############
# Building #
############

.PHONY: build-in-docker
build-in-docker:
	$(CONTAINER_CMD) $(MAKE) $(MFLAGS) build

.PHONY: build
build: operator

.PHONY: operator
operator: $(GOLANG_FILES)
	$(GO_BUILD_RECIPE) -o operator $(GO_PKG)/cmd/operator

# We need this Make target so that we can build the operator depending
# only on what is checked into the repo, without calling to the internet.
.PHONY: operator-no-deps
operator-no-deps:
	$(GO_BUILD_RECIPE) -o operator $(GO_PKG)/cmd/operator

.PHONY: image
image: .hack-operator-image

.hack-operator-image: Dockerfile
# Create empty target file, for the sole purpose of recording when this target
# was last executed via the last-modification timestamp on the file. See
# https://www.gnu.org/software/make/manual/make.html#Empty-Targets
	docker build -t $(REPO):$(TAG) .
	touch $@

##############
# Generating #
##############

vendor:
	go mod tidy
	go mod vendor
	go mod verify

.PHONY: generate
generate: $(EMBEDMD_BIN) merge-cluster-roles pkg/manifests/bindata.go docs

.PHONY: generate-in-docker
generate-in-docker:
	$(CONTAINER_CMD) $(MAKE) $(MFLAGS) generate

jsonnet/vendor: jsonnet/jsonnetfile.json
	cd jsonnet && jb install

$(ASSETS): $(JSONNET_SRC) $(JSONNET_VENDOR) hack/build-jsonnet.sh
	./hack/build-jsonnet.sh

pkg/manifests/bindata.go: $(GOBINDATA_BIN) $(ASSETS)
	# Using "-modtime 1" to make generate target deterministic. It sets all file time stamps to unix timestamp 1
	go-bindata -mode 420 -modtime 1 -pkg manifests -o $@ assets/...

merge-cluster-roles: manifests/02-role.yaml
manifests/02-role.yaml: $(ASSETS) hack/merge_cluster_roles.py hack/cluster-monitoring-operator-role.yaml.in
	python2 hack/merge_cluster_roles.py hack/cluster-monitoring-operator-role.yaml.in `find assets | grep role | grep -v "role-binding" | sort` > manifests/02-role.yaml

.PHONY: docs
docs:
	embedmd -w `find Documentation -name "*.md"`

##############
# Formatting #
##############

.PHONY: format
format: go-fmt shellcheck

.PHONY: go-fmt
go-fmt:
	go fmt $(PKGS)

.PHONY: shellcheck
shellcheck:
	docker run -v "${PWD}:/mnt" koalaman/shellcheck:stable $(shell find . -type f -name "*.sh" -not -path "*vendor*")

###########
# Testing #
###########

.PHONY: test
test: test-unit test-e2e

.PHONY: test-unit
test-unit:
	go test -race -short $(PKGS) -count=1

.PHONY: test-e2e
test-e2e: KUBECONFIG?=$(HOME)/.kube/config
test-e2e:
	go test -v -timeout=20m ./test/e2e/ --kubeconfig $(KUBECONFIG)

############
# Binaries #
############

$(EMBEDMD_BIN):
	go get -u github.com/campoy/embedmd

$(GOBINDATA_BIN):
	go get -u github.com/jteeuwen/go-bindata/...

$(JB_BINARY):
	go get -u github.com/jsonnet-bundler/jsonnet-bundler/cmd/jb

$(GOJSONTOYAML_BINARY):
	go get -u github.com/brancz/gojsontoyaml
