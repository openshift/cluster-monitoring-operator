FROM registry.svc.ci.openshift.org/ocp/builder:golang-1.10 AS builder
WORKDIR /go/src/github.com/openshift/cluster-monitoring-operator
COPY . .
RUN make operator-no-deps

FROM registry.svc.ci.openshift.org/ocp/4.0:base
COPY --from=builder /go/src/github.com/openshift/cluster-monitoring-operator/operator /usr/bin/
COPY manifests /manifests
USER 1001
ENTRYPOINT ["/usr/bin/operator"]
LABEL io.k8s.display-name="OpenShift cluster-monitoring-operator" \
      io.k8s.description="This is a component of OpenShift and manages the lifecycle of the Prometheus based cluster monitoring stack." \
      io.openshift.tags="openshift" \
      io.openshift.release.operator=true \
      maintainer="Frederic Branczyk <fbranczy@redhat.com>"
