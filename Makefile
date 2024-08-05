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

# go packages for unit tests, excluding e2e tests
PKGS=$(shell go list ./... | grep -v /test/e2e)
GOLANG_FILES:=$(shell find . -name \*.go -print)
# NOTE: grep -v %.yaml is needed  because "%s-policy.yaml" is used
# in manifest.go and that isn't a valid asset.
# NOTE: Certain paths included in the manifest.go file are not valid
# asset paths and should be excluded from the list of assets. These
# paths are:
# - /etc/
ASSETS=$(shell grep -oh '[^"]*/.*\.yaml' pkg/manifests/manifests.go \
          | grep -v '^/etc' \
          | grep -v '%.*yaml' | sed 's/^/assets\//')

BIN_DIR ?= $(shell pwd)/tmp/bin

# Docgen related variables
TYPES_TARGET=pkg/manifests/types.go
K8S_VERSION=$(shell echo -n v1. &&  cat go.mod | grep -w "k8s.io/api" | awk '{ print $$2 }' | cut -d "." -f 2)
PO_VERSION=$(shell cat go.mod | grep "github.com/prometheus-operator/prometheus-operator[^=>]\+$$" | awk '{ print $$2 }' | sort -u)

EMBEDMD_BIN=$(BIN_DIR)/embedmd
JB_BIN=$(BIN_DIR)/jb
GOJSONTOYAML_BIN=$(BIN_DIR)/gojsontoyaml
JSONNET_BIN=$(BIN_DIR)/jsonnet
JSONNETFMT_BIN=$(BIN_DIR)/jsonnetfmt
GOLANGCI_LINT_BIN=$(BIN_DIR)/golangci-lint
GOLANGCI_LINT_VERSION=v1.55.2
PROMTOOL_BIN=$(BIN_DIR)/promtool
DOCGEN_BIN=$(BIN_DIR)/docgen
MISSPELL_BIN=$(BIN_DIR)/misspell
TOOLING=$(EMBEDMD_BIN) $(JB_BIN) $(GOJSONTOYAML_BIN) $(JSONNET_BIN) $(JSONNETFMT_BIN) $(PROMTOOL_BIN) $(DOCGEN_BIN) $(GOLANGCI_LINT_BIN)

MANIFESTS_DIR ?= $(shell pwd)/manifests
JSON_MANIFESTS_DIR ?= $(shell pwd)/tmp/json-manifests/manifests
MANIFESTS ?= $(wildcard $(MANIFESTS_DIR)/*.yaml)
JSON_MANIFESTS ?= $(patsubst $(MANIFESTS_DIR)%,$(JSON_MANIFESTS_DIR)%,$(patsubst %.yaml,%.json,$(MANIFESTS)))

JSONNET_SRC=$(shell find ./jsonnet -type f -not -path "./jsonnet/vendor*")
JSONNET_VENDOR=jsonnet/vendor

GO_BUILD_RECIPE=GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build --ldflags="-s -X $(GO_PKG)/pkg/operator.Version=$(VERSION)"
MARKDOWN_DOCS=$(shell find . -type f -name '*.md' ! -path '*/vendor/*' ! -path './git/*'  \
				! -name 'data-collection.md' ! -name 'sample-metrics.md' | sort)

.PHONY: all
all: clean format generate build test

.PHONY: clean
clean:
	rm -rf $(JSONNET_VENDOR) operator .hack-operator-image tmp/

############
# Building #
############

# run-local builds and runs operator out of cluster.
# use make run-local SWITCH_TO_CMO=false to not switch the login to CMO
# service-account. E.g. when logged in kube:admin and what to run operator
# as kube:admin
.PHONY: run-local
run-local: build
	@if $${SWITCH_TO_CMO:-true} ; then \
		PATH="$(PATH):$(BIN_DIR)" \
		KUBECONFIG=$(KUBECONFIG)  ./hack/local-cmo.sh ;\
	else \
		PATH="$(PATH):$(BIN_DIR)" \
		KUBECONFIG=$(KUBECONFIG) ./hack/local-cmo.sh --no-cmo-login ;\
	fi

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

.PHONY: update-go-deps
update-go-deps:
	for m in $$(go list -mod=readonly -m -f '{{ if and (not .Indirect) (not .Main)}}{{.Path}}{{end}}' all); do \
		go get $$m; \
	done
	@echo "Don't forget to run 'make vendor'"

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
build-jsonnet: $(JSONNET_BIN) $(GOJSONTOYAML_BIN) $(JSONNET_SRC) $(JSONNET_VENDOR) json-manifests json-crds
	./hack/build-jsonnet.sh

$(JSON_MANIFESTS): $(MANIFESTS)
	cat $(MANIFESTS_DIR)/$(patsubst %.json,%.yaml,$(@F)) | $(GOJSONTOYAML_BIN) -yamltojson > $@

.PHONY: json-manifests
json-manifests: $(JSON_MANIFESTS_DIR) $(JSON_MANIFESTS)

.PHONY: json-crds
json-crds: jsonnet/crds/alertingrules-custom-resource-definition.json jsonnet/crds/alertrelabelconfigs-custom-resource-definition.json

jsonnet/crds/alertingrules-custom-resource-definition.json: vendor/github.com/openshift/api/monitoring/v1/zz_generated.crd-manifests/0000_50_monitoring_01_alertingrules.crd.yaml
	$(GOJSONTOYAML_BIN) -yamltojson < $< > $@

jsonnet/crds/alertrelabelconfigs-custom-resource-definition.json: vendor/github.com/openshift/api/monitoring/v1/zz_generated.crd-manifests/0000_50_monitoring_02_alertrelabelconfigs.crd.yaml
	$(GOJSONTOYAML_BIN) -yamltojson < $< > $@

.PHONY: versions
versions:
	@cd ./hack/go && go mod tidy && go mod download && go run -mod=mod generate_versions.go

.PHONY: check-versions
check-versions: VERSION_FILE=jsonnet/versions.yaml
check-versions:
	export VERSION_FILE=$(VERSION_FILE) && $(MAKE) versions && git diff --exit-code -- ${VERSION_FILE}

.PHONY: docs
docs: $(EMBEDMD_BIN) $(DOCGEN_BIN) Documentation/telemetry/telemeter_query
	$(EMBEDMD_BIN) -w `find Documentation -name "*.md"`
	$(DOCGEN_BIN) api markdown $(K8S_VERSION) $(PO_VERSION) $(TYPES_TARGET) > Documentation/api.md
	$(DOCGEN_BIN) api asciidocs $(K8S_VERSION) $(PO_VERSION) $(TYPES_TARGET)
	$(DOCGEN_BIN) resources markdown > Documentation/resources.md
	$(DOCGEN_BIN) resources asciidocs > Documentation/resources.adoc

Documentation/telemetry/telemeter_query: manifests/0000_50_cluster-monitoring-operator_04-config.yaml hack/telemeter_query.go
	go generate ./hack/telemeter_query.go > Documentation/telemetry/telemeter_query

##############
# Formatting #
##############

.PHONY: format
format: go-fmt golangci-lint shellcheck jsonnet-fmt misspell

.PHONY: go-fmt
go-fmt:
	go fmt ./...

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT_BIN)
	$(GOLANGCI_LINT_BIN) run --verbose --print-resources-usage

.PHONY: golangci-lint-fix
golangci-lint-fix: $(GOLANGCI_LINT_BIN)
	$(GOLANGCI_LINT_BIN) run --verbose --print-resources-usage --fix

.PHONY:
misspell:
	$(MISSPELL_BIN) -error $(MARKDOWN_DOCS)

.PHONY:
misspell-fix:
	$(MISSPELL_BIN) -w $(MARKDOWN_DOCS)

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

.PHONY: bench
bench:
	go test -run NONE -bench ^Bench -benchmem $(PKGS)

.PHONY: test
test: test-unit test-rules test-e2e

.PHONY: test-unit
test-unit:
	go test -run ^Test -race -short $(PKGS) -count=1

.PHONY: test-e2e
test-e2e: KUBECONFIG?=$(HOME)/.kube/config
test-e2e:
	go test -run ^Test -v -timeout=150m ./test/e2e/ --kubeconfig $(KUBECONFIG)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(JSON_MANIFESTS_DIR):
	mkdir -p $(JSON_MANIFESTS_DIR)

$(TOOLING): $(BIN_DIR)
	@echo Installing tools from hack/tools/tools.go
	@cd hack/tools && go list -mod=mod -tags tools -e -f '{{ range .Imports }}{{ printf "%s\n" .}}{{end}}' ./ | xargs -tI % go build -mod=mod -o $(BIN_DIR) %
	@GOBIN=$(BIN_DIR) go install $(GO_PKG)/hack/docgen
	curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh| sh -s -- -b $(BIN_DIR) $(GOLANGCI_LINT_VERSION)
