# When bumping the Go version, don't forget to update the configuration of the
# CI jobs in openshift/release.
FROM registry.ci.openshift.org/ocp/builder:rhel-9-golang-1.24-openshift-4.20 AS builder
WORKDIR /go/src/github.com/openshift/cluster-monitoring-operator
COPY . .
ENV GOFLAGS="-mod=vendor"
RUN make operator-no-deps && make tests-ext-build && gzip tests-ext

FROM registry.ci.openshift.org/ocp/4.20:base-rhel9
LABEL io.k8s.display-name="OpenShift cluster-monitoring-operator" \
      io.k8s.description="This is a component of OpenShift and manages the lifecycle of the Prometheus based cluster monitoring stack." \
      io.openshift.tags="openshift" \
      io.openshift.release.operator=true \
      summary="This is a component of OpenShift and manages the lifecycle of the Prometheus based cluster monitoring stack." \
      maintainer="OpenShift Monitoring Team <team-monitoring@redhat.com>"

COPY --from=builder /go/src/github.com/openshift/cluster-monitoring-operator/operator /usr/bin/
COPY --from=builder /go/src/github.com/openshift/cluster-monitoring-operator/tests-ext.gz /usr/bin/cluster-monitoring-operator-tests-ext.gz
COPY manifests /manifests
COPY assets /assets
USER 1001
ENTRYPOINT ["/usr/bin/operator"]
