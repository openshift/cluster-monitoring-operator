all: build

APP_NAME=cluster-monitoring-operator
MAIN_PKG=github.com/openshift/$(APP_NAME)/cmd/operator
REPO?=quay.io/coreos/$(APP_NAME)
TAG?=$(shell git rev-parse --short HEAD)
ENVVAR = GOOS=linux GOARCH=amd64 CGO_ENABLED=0
NAMESPACE=openshift-monitoring
KUBECONFIG?=$(HOME)/.kube/config
PKGS   = $(shell go list ./... | grep -v -E '/vendor/|/test|/examples')
GOOS   = linux
VERSION=$(shell cat VERSION | tr -d " \t\n\r")

build:
	GOOS=$(GOOS) go build --ldflags="-s -X github.com/openshift/cluster-monitoring-operator/pkg/operator.Version=$(VERSION)" -o operator $(MAIN_PKG)

run:
	./operator

crossbuild:
	$(ENVVAR) $(MAKE) build

container:
	docker build -t $(REPO):$(TAG) .

push: container
	docker push $(REPO):$(TAG)

clean:
	rm operator
	go clean -r $(MAIN_PKG)
	docker images -q $(REPO) | xargs docker rmi --force

embedmd:
	@go get github.com/campoy/embedmd

docs: embedmd
	embedmd -w `find Documentation -name "*.md"`

assets: gobindata
	hack/generate-rules-configmap.sh k8s > assets/prometheus-k8s/prometheus-k8s-rules.yaml
	#hack/generate-rules-configmap.sh kube-system etcd > assets/prometheus-etcd/prometheus-etcd-rules.yaml
	hack/generate-alertmanager-secret.sh > assets/alertmanager/alertmanager-config.yaml
	# Using "-modtime 1" to make generate target deterministic. It sets all file time stamps to unix timestamp 1
	go-bindata -mode 420 -modtime 1 -pkg manifests -o pkg/manifests/bindata.go assets/...

generate:
	docker build -t tpo-generate -f Dockerfile.generate .
	docker run --rm  --security-opt label=disable -v `pwd`:/go/src/github.com/openshift/cluster-monitoring-operator -w /go/src/github.com/openshift/cluster-monitoring-operator tpo-generate make merge-cluster-roles assets docs

gobindata:
	go get -u github.com/jteeuwen/go-bindata/...

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
	python2 hack/merge_cluster_roles.py manifests/cluster-monitoring-operator-role.yaml.in `echo assets/*/*role.yaml` > manifests/cluster-monitoring-operator-role.yaml

.PHONY: all build run crossbuild container push clean deps generate gobindata test e2e-test e2e-clean
