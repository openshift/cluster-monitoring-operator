FROM openshift/origin-release:golang-1.10 AS builder

COPY . /go/src/github.com/openshift/cluster-monitoring-operator
RUN cd /go/src/github.com/openshift/cluster-monitoring-operator && \
    make operator-no-deps

FROM openshift/origin-base

COPY --from=builder /go/src/github.com/openshift/cluster-monitoring-operator/operator /usr/bin/
COPY manifests /manifests

LABEL io.k8s.display-name="OpenShift cluster-monitoring-operator" \
      io.k8s.description="This is a component of OpenShift Container Platform and manages the lifecycle of the Prometheus based cluster monitoring stack." \
      io.openshift.tags="openshift" \
      io.openshift.release.operator=true \
      maintainer="Frederic Branczyk <fbranczy@redhat.com>"

# doesn't require a root user.
USER 1001

ENTRYPOINT ["/usr/bin/operator"]
