SHELL=/usr/bin/env bash -o pipefail

GO_PKG=github.com/openshift/cluster-monitoring-operator
REPO?=quay.io/openshift/cluster-monitoring-operator
TAG?=$(shell git rev-parse --short HEAD)
VERSION=$(shell cat VERSION | tr -d " \t\n\r")
GO111MODULE?=on
GOPROXY?=http://proxy.golang.org
export GO111MODULE
export GOPROXY

PKGS=$(shell go list ./... | grep -v -E '/vendor/|/test|/examples')
GOLANG_FILES:=$(shell find . -name \*.go -print) pkg/manifests/bindata.go
FIRST_GOPATH:=$(firstword $(subst :, ,$(shell go env GOPATH)))
EMBEDMD_BIN=$(FIRST_GOPATH)/bin/embedmd
GOBINDATA_BIN=$(FIRST_GOPATH)/bin/go-bindata
JB_BINARY=$(FIRST_GOPATH)/bin/jb
GOJSONTOYAML_BINARY=$(FIRST_GOPATH)/bin/gojsontoyaml
PROMTOOL_BINARY=$(FIRST_GOPATH)/bin/promtool
ASSETS=$(shell grep -oh 'assets/.*\.yaml' pkg/manifests/manifests.go)
JSONNET_SRC=$(shell find ./jsonnet -type f)
JSONNET_VENDOR=jsonnet/jsonnetfile.lock.json jsonnet/vendor

GO_BUILD_RECIPE=GOOS=linux CGO_ENABLED=0 go build --ldflags="-s -X $(GO_PKG)/pkg/operator.Version=$(VERSION)"
CONTAINER_CMD:=docker run --rm \
		-u="$(shell id -u):$(shell id -g)" \
		-v "$(shell go env GOCACHE):/.cache/go-build:Z" \
		-v "$(PWD):/go/src/$(GO_PKG):Z" \
		-w "/go/src/$(GO_PKG)" \
		-e GO111MODULE=$(GO111MODULE) \
		quay.io/coreos/jsonnet-ci:release-0.39

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

.hack-operator-image: Dockerfile operator
# Create empty target file, for the sole purpose of recording when this target
# was last executed via the last-modification timestamp on the file. See
# https://www.gnu.org/software/make/manual/make.html#Empty-Targets
	docker build -t $(REPO):$(TAG) .
	touch $@

##############
# Generating #
##############

.PHONY: vendor
vendor:
	go mod tidy
	go mod vendor
	go mod verify

.PHONY: generate
generate: $(EMBEDMD_BIN) merge-cluster-roles pkg/manifests/bindata.go docs

.PHONY: generate-in-docker
generate-in-docker:
	$(CONTAINER_CMD) $(MAKE) $(MFLAGS) generate

jsonnet/vendor: $(JB_BINARY) jsonnet/jsonnetfile.json
	cd jsonnet && jb install

$(ASSETS): $(JSONNET_SRC) $(JSONNET_VENDOR) $(GOJSONTOYAML_BINARY) hack/build-jsonnet.sh
	./hack/build-jsonnet.sh

pkg/manifests/bindata.go: $(GOBINDATA_BIN) $(ASSETS)
	# Using "-modtime 1" to make generate target deterministic. It sets all file time stamps to unix timestamp 1
	go-bindata -mode 420 -modtime 1 -pkg manifests -o $@ assets/...

merge-cluster-roles: manifests/0000_50_cluster_monitoring_operator_02-role.yaml
manifests/0000_50_cluster_monitoring_operator_02-role.yaml: $(ASSETS) hack/merge_cluster_roles.py hack/cluster-monitoring-operator-role.yaml.in
	python2 hack/merge_cluster_roles.py hack/cluster-monitoring-operator-role.yaml.in `find assets | grep role | grep -v "role-binding" | sort` > $@

.PHONY: docs
docs: Documentation/telemeter_query
	embedmd -w `find Documentation -name "*.md"`

Documentation/telemeter_query: manifests/0000_50_cluster_monitoring_operator_04-config.yaml hack/telemeter_query.go
	go generate ./hack/telemeter_query.go > Documentation/telemeter_query

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
	hack/shellcheck.sh

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
test-e2e: $(PROMTOOL_BINARY)
	go test -v -timeout=20m ./test/e2e/ --kubeconfig $(KUBECONFIG) --promtool $(PROMTOOL_BINARY)

.PHONY: test-sec
test-sec:
	@which gosec 2> /dev/null >&1 || { echo "gosec must be installed to lint code";  exit 1; }
	gosec -severity medium --confidence medium -quiet ./...

############
# Binaries #
############

$(EMBEDMD_BIN):
	@go install -mod=vendor github.com/campoy/embedmd

$(GOBINDATA_BIN):
	@go install -mod=vendor github.com/go-bindata/go-bindata/...

$(JB_BINARY):
	@go install -mod=vendor github.com/jsonnet-bundler/jsonnet-bundler/cmd/jb

$(GOJSONTOYAML_BINARY):
	@go install -mod=vendor github.com/brancz/gojsontoyaml

$(PROMTOOL_BINARY):
	@GO111MODULE=off go get github.com/prometheus/prometheus/cmd/promtool
