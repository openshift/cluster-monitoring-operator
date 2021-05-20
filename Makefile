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
GOLANG_FILES:=$(shell find . -name \*.go -print)
ASSETS=$(shell grep -oh '[^"]*/.*\.yaml' pkg/manifests/manifests.go | sed 's/^/assets\//')

BIN_DIR ?= $(shell pwd)/tmp/bin

EMBEDMD_BIN=$(BIN_DIR)/embedmd
JB_BIN=$(BIN_DIR)/jb
GOJSONTOYAML_BIN=$(BIN_DIR)/gojsontoyaml
JSONNET_BIN=$(BIN_DIR)/jsonnet
JSONNETFMT_BIN=$(BIN_DIR)/jsonnetfmt
PROMTOOL_BIN=$(BIN_DIR)/promtool
TOOLING=$(EMBEDMD_BIN) $(GOBINDATA_BIN) $(JB_BIN) $(GOJSONTOYAML) $(JSONNET_BIN) $(JSONNETFMT_BIN) $(PROMTOOL_BIN)

MANIFESTS_DIR ?= $(shell pwd)/manifests
JSON_MANIFESTS_DIR ?= $(shell pwd)/tmp/json-manifests/manifests
MANIFESTS ?= $(wildcard $(MANIFESTS_DIR)/*.yaml)
JSON_MANIFESTS ?= $(patsubst $(MANIFESTS_DIR)%,$(JSON_MANIFESTS_DIR)%,$(patsubst %.yaml,%.json,$(MANIFESTS)))

JSONNET_SRC=$(shell find ./jsonnet -type f -not -path "./jsonnet/vendor*")
JSONNET_VENDOR=jsonnet/vendor

GO_BUILD_RECIPE=GOOS=linux CGO_ENABLED=0 go build --ldflags="-s -X $(GO_PKG)/pkg/operator.Version=$(VERSION)"

.PHONY: all
all: clean format generate build test

.PHONY: clean
clean:
	rm -rf $(JSONNET_VENDOR) operator .hack-operator-image tmp/

############
# Building #
############

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
generate: build-jsonnet manifests/0000_50_cluster-monitoring-operator_02-role.yaml docs check-assets

.PHONY: generate-in-docker
generate-in-docker:
	echo -e "FROM golang:1.14 \n RUN apt update && apt install python-yaml jq -y \n RUN mkdir /.cache && chown $(shell id -u):$(shell id -g) /.cache" | docker build -t cmo-tooling -
	docker run -it --user $(shell id -u):$(shell id -g) \
		-w /go/src/github.com/openshift/cluster-monitoring-operator \
		-v ${PWD}:/go/src/github.com/openshift/cluster-monitoring-operator \
		cmo-tooling make generate


$(JSONNET_VENDOR): $(JB_BIN) jsonnet/jsonnetfile.json
	cd jsonnet && $(JB_BIN) install

$(ASSETS): build-jsonnet
	# Check if files were properly generated
	[ -f "$@" ] || exit 1

.PHONY: build-jsonnet
build-jsonnet: $(JSONNET_BIN) $(GOJSONTOYAML_BIN) $(JSONNET_SRC) $(JSONNET_VENDOR) json-manifests
	./hack/build-jsonnet.sh

$(JSON_MANIFESTS): $(MANIFESTS)
	cat $(MANIFESTS_DIR)/$(patsubst %.json,%.yaml,$(@F)) | $(GOJSONTOYAML_BIN) -yamltojson > $@

.PHONY: json-manifests
json-manifests: $(JSON_MANIFESTS_DIR) $(JSON_MANIFESTS)

# Merge cluster roles
manifests/0000_50_cluster-monitoring-operator_02-role.yaml: hack/merge_cluster_roles.py hack/cluster-monitoring-operator-role.yaml.in $(ASSETS)
	python2 hack/merge_cluster_roles.py hack/cluster-monitoring-operator-role.yaml.in `find assets | grep role | grep -v "role-binding"` > $@

.PHONY: docs
docs: $(EMBEDMD_BIN) Documentation/telemeter_query
	$(EMBEDMD_BIN) -w `find Documentation -name "*.md"`

Documentation/telemeter_query: manifests/0000_50_cluster-monitoring-operator_04-config.yaml hack/telemeter_query.go
	go generate ./hack/telemeter_query.go > Documentation/telemeter_query

##############
# Formatting #
##############

.PHONY: format
format: go-fmt shellcheck jsonnet-fmt check-rules

.PHONY: go-fmt
go-fmt:
	go fmt $(PKGS)

.PHONY: jsonnet-fmt
jsonnet-fmt: $(JSONNETFMT_BIN)
	find jsonnet/ -name 'vendor' -prune -o -name '*.libsonnet' -print -o -name '*.jsonnet' -print | xargs -n 1 -- $(JSONNETFMT_BIN) -i

.PHONY: shellcheck
shellcheck:
	hack/shellcheck.sh

tmp/rules.yaml: $(GOJSONTOYAML_BIN) $(ASSETS)
	mkdir -p tmp/rules
	hack/find-rules.sh | $(GOJSONTOYAML_BIN) > tmp/rules.yaml

.PHONY: check-rules
check-rules: $(PROMTOOL_BIN) tmp/rules.yaml
	rm -f tmp/"$@".out
	@$(PROMTOOL_BIN) check rules tmp/rules.yaml | tee "tmp/$@.out"

.PHONY: test-rules
test-rules: check-rules
	hack/test-rules.sh | tee "tmp/$@.out"

.PHONY: check-assets
check-assets:
	hack/check-assets.sh

###########
# Testing #
###########

.PHONY: test
test: test-unit test-e2e

# TODO(simonpasquier): we should have a CI job specifically checking Prometheus rules.
.PHONY: test-unit
test-unit: test-rules
	go test -race -short $(PKGS) -count=1

.PHONY: test-e2e
test-e2e: KUBECONFIG?=$(HOME)/.kube/config
test-e2e:
	go test -v -timeout=30m ./test/e2e/ --kubeconfig $(KUBECONFIG)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(JSON_MANIFESTS_DIR):
	mkdir -p $(JSON_MANIFESTS_DIR)

$(TOOLING): $(BIN_DIR)
	@echo Installing tools from hack/tools.go
	@cd hack/tools && go list -mod=mod -tags tools -f '{{ range .Imports }}{{ printf "%s\n" .}}{{end}}' ./ | xargs -tI % go build -mod=mod -o $(BIN_DIR) %
