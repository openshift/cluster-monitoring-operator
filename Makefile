SHELL=/usr/bin/env bash -o pipefail

GO_PKG=github.com/openshift/cluster-monitoring-operator
REPO?=quay.io/openshift/cluster-monitoring-operator
TAG?=$(shell git rev-parse --short HEAD)
VERSION=$(shell cat VERSION | tr -d " \t\n\r")

GOOS?=$(shell go env GOOS)
GOARCH?=$(shell go env GOARCH)
GO111MODULE?=on
GOPROXY?=http://proxy.golang.org
export GO111MODULE
export GOPROXY

# go pakages for unit tests, excluding e2e tests
PKGS=$(shell go list ./... | grep -v /test/e2e)
GOLANG_FILES:=$(shell find . -name \*.go -print)
# NOTE: grep -v %.yaml is needed  because "%s-policy.yaml" is used
# in manifest.go and that isn't a valid asset.
ASSETS=$(shell grep -oh '[^"]*/.*\.yaml' pkg/manifests/manifests.go \
          | grep -v '%.*yaml' | sed 's/^/assets\//')

BIN_DIR ?= $(shell pwd)/tmp/bin

EMBEDMD_BIN=$(BIN_DIR)/embedmd
JB_BIN=$(BIN_DIR)/jb
GOJSONTOYAML_BIN=$(BIN_DIR)/gojsontoyaml
JSONNET_BIN=$(BIN_DIR)/jsonnet
JSONNETFMT_BIN=$(BIN_DIR)/jsonnetfmt
PROMTOOL_BIN=$(BIN_DIR)/promtool
TOOLING=$(EMBEDMD_BIN) $(JB_BIN) $(GOJSONTOYAML_BIN) $(JSONNET_BIN) $(JSONNETFMT_BIN) $(PROMTOOL_BIN)

MANIFESTS_DIR ?= $(shell pwd)/manifests
JSON_MANIFESTS_DIR ?= $(shell pwd)/tmp/json-manifests/manifests
MANIFESTS ?= $(wildcard $(MANIFESTS_DIR)/*.yaml)
JSON_MANIFESTS ?= $(patsubst $(MANIFESTS_DIR)%,$(JSON_MANIFESTS_DIR)%,$(patsubst %.yaml,%.json,$(MANIFESTS)))

JSONNET_SRC=$(shell find ./jsonnet -type f -not -path "./jsonnet/vendor*")
JSONNET_VENDOR=jsonnet/vendor

GO_BUILD_RECIPE=GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build --ldflags="-s -X $(GO_PKG)/pkg/operator.Version=$(VERSION)"

.PHONY: all
all: clean format generate build test

.PHONY: clean
clean:
	rm -rf $(JSONNET_VENDOR) operator .hack-operator-image tmp/

############
# Building #
############

.PHONY: run-local
run-local: build
	KUBECONFIG=$(KUBECONFIG) ./hack/local-cmo.sh

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

.PHONY: update
update: $(JB_BIN)
	cd jsonnet && $(JB_BIN) update $(COMPONENTS)

.PHONY: generate
generate: build-jsonnet docs

.PHONY: verify
verify: check-assets check-rules check-runbooks

# TODO(paulfantom): generate-in-docker can be completely removed after OpenShift 4.7 is EOL
.PHONY: generate-in-docker
generate-in-docker:
	echo -e "FROM golang:1.14 \n RUN apt update && apt install python-yaml jq -y \n RUN mkdir /.cache && chown $(shell id -u):$(shell id -g) /.cache" | docker build -t cmo-tooling -
	docker run -it --user $(shell id -u):$(shell id -g) \
		-w /go/src/github.com/openshift/cluster-monitoring-operator \
		-v ${PWD}:/go/src/github.com/openshift/cluster-monitoring-operator \
		cmo-tooling make generate


$(JSONNET_VENDOR): $(JB_BIN) jsonnet/jsonnetfile.json jsonnet/jsonnetfile.lock.json
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

.PHONY: versions
versions: $(GOJSONTOYAML_BIN)
	./hack/generate-versions.sh

.PHONY: docs
docs: $(EMBEDMD_BIN) Documentation/telemetry/telemeter_query
	$(EMBEDMD_BIN) -w `find Documentation -name "*.md"`

Documentation/telemetry/telemeter_query: manifests/0000_50_cluster-monitoring-operator_04-config.yaml hack/telemeter_query.go
	go generate ./hack/telemeter_query.go > Documentation/telemetry/telemeter_query

##############
# Formatting #
##############

.PHONY: format
format: go-fmt shellcheck jsonnet-fmt

.PHONY: go-fmt
go-fmt:
	go fmt ./...

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

.PHONY: check-runbooks
check-runbooks:
	# Get runbook urls from the alerts annotations and test if a link is broken
	# with wget. It also make sure that the command succeed when there are no urls.
	@grep -rho 'runbook_url.*' assets || true | cut -f2- -d: | wget --spider -nv -i -

###########
# Testing #
###########

.PHONY: test
test: test-unit test-rules test-e2e

.PHONY: test-unit
test-unit:
	go test -race -short $(PKGS) -count=1

.PHONY: test-e2e
test-e2e: KUBECONFIG?=$(HOME)/.kube/config
test-e2e:
	go test -v -timeout=120m ./test/e2e/ --kubeconfig $(KUBECONFIG)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(JSON_MANIFESTS_DIR):
	mkdir -p $(JSON_MANIFESTS_DIR)

$(TOOLING): $(BIN_DIR)
	@echo Installing tools from hack/tools.go
	@cd hack/tools && go list -mod=mod -tags tools -f '{{ range .Imports }}{{ printf "%s\n" .}}{{end}}' ./ | xargs -tI % go build -mod=mod -o $(BIN_DIR) %
