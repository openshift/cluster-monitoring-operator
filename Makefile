all: build

APP_NAME=cluster-monitoring-operator
BIN=operator
MAIN_PKG=github.com/openshift/$(APP_NAME)/cmd/operator
REPO?=quay.io/coreos/$(APP_NAME)
TAG?=$(shell git rev-parse --short HEAD)
ENVVAR=GOOS=linux GOARCH=amd64 CGO_ENABLED=0
NAMESPACE=openshift-monitoring
KUBECONFIG?=$(HOME)/.kube/config
PKGS=$(shell go list ./... | grep -v -E '/vendor/|/test|/examples')
GOOS=linux
VERSION=$(shell cat VERSION | tr -d " \t\n\r")
SRC=$(shell find . -type f -name '*.go') pkg/manifests/bindata.go
GOBINDATA_BIN=$(GOPATH)/bin/go-bindata
GOJSONTOYAML_BIN=$(GOPATH)/bin/gojsontoyaml
# We need jsonnet on Travis; here we default to the user's installed jsonnet binary; if nothing is installed, then install go-jsonnet.
JSONNET_BIN=$(if $(shell which jsonnet 2>/dev/null),$(shell which jsonnet 2>/dev/null),$(GOPATH)/bin/jsonnet)
JB_BIN=$(GOPATH)/bin/jb
ASSETS=$(shell grep -oh 'assets/.*\.yaml' pkg/manifests/manifests.go)
JSONNET_SRC=$(shell find ./jsonnet -type f)
JSONNET_VENDOR=$(addprefix jsonnet/vendor/, $(sort $(shell grep -oh "'.*libsonnet'" ./jsonnet/* --exclude-dir=./jsonnet/vendor | tr -d "'")))

build: $(BIN)

$(BIN): $(SRC)
	GOOS=$(GOOS) go build --ldflags="-s -X github.com/openshift/cluster-monitoring-operator/pkg/operator.Version=$(VERSION)" -o $@ $(MAIN_PKG)

run: build
	./$(BIN)

crossbuild:
	$(ENVVAR) $(MAKE) build

container:
	docker build -t $(REPO):$(TAG) .

push: container
	docker push $(REPO):$(TAG)

clean:
	rm $(BIN)
	go clean -r $(MAIN_PKG)
	docker images -q $(REPO) | xargs docker rmi --force

embedmd:
	@go get github.com/campoy/embedmd

docs: embedmd
	embedmd -w `find Documentation -name "*.md"`

bindata: pkg/manifests/bindata.go
pkg/manifests/bindata.go: $(ASSETS) $(GOBINDATA_BIN)
	# Using "-modtime 1" to make generate target deterministic. It sets all file time stamps to unix timestamp 1
	go-bindata -mode 420 -modtime 1 -pkg manifests -o $@ assets/...

$(ASSETS): $(JSONNET_SRC) $(JSONNET_BIN) $(GOJSONTOYAML_BIN) $(JSONNET_VENDOR)
	./hack/build-jsonnet.sh

$(JSONNET_VENDOR): $(JB_BIN)
	cd jsonnet && jb install

generate:
	docker build -t tpo-generate -f Dockerfile.generate .
	docker run --rm --security-opt label=disable -v `pwd`:/go/src/github.com/openshift/cluster-monitoring-operator -w /go/src/github.com/openshift/cluster-monitoring-operator tpo-generate make merge-cluster-roles bindata docs

gobindata: $(GOBINDATA_BIN)
$(GOBINDATA_BIN):
	go get -u github.com/jteeuwen/go-bindata/...

gojsontoyaml: $(GOJSONTOYAML_BIN)
$(GOJSONTOYAML_BIN):
	go get -u github.com/brancz/gojsontoyaml

jb: $(JB_BIN)
$(JB_BIN):
	go get -u github.com/jsonnet-bundler/jsonnet-bundler/cmd/jb

jsonnet: $(JSONNET_BIN)
$(JSONNET_BIN):
	go get -u github.com/google/go-jsonnet/jsonnet

test-unit:
	go test $(PKGS)

test: e2e-test

vendor:
	govendor add +external

e2e-test:
	go test -v -timeout=20m ./test/e2e/ --operator-image=$(REPO):$(TAG) --kubeconfig $(KUBECONFIG)

e2e-clean:
	kubectl -n $(NAMESPACE) delete appversion,prometheus,alertmanager,servicemonitor,statefulsets,deploy,svc,endpoints,pods,cm,secrets,replicationcontrollers,thirdpartyresource --all --ignore-not-found
	kubectl delete namespace $(NAMESPACE)

build-docker-test:
	sed 's/DOCKER_IMAGE_TAG/$(TAG)/' Dockerfile.test > Dockerfile.test.generated
	docker build -f Dockerfile.test.generated -t quay.io/coreos/cluster-monitoring-operator-test:$(TAG) .

run-docker-test-minikube:
	docker run --rm -it --env KUBECONFIG=/kubeconfig -v /home/$(USER)/.kube/config:/kubeconfig -v /home/$(USER)/.minikube:/home/$(USER)/.minikube quay.io/coreos/cluster-monitoring-operator-test:$(TAG)

merge-cluster-roles:
	python2 hack/merge_cluster_roles.py manifests/cluster-monitoring-operator-role.yaml.in `find assets | grep role | grep -v "role-binding" | sort` > manifests/cluster-monitoring-operator-role.yaml

.PHONY: all build run crossbuild container push clean deps generate bindata gobindata gojsontoyaml jsonnet test e2e-test e2e-clean
