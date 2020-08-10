# When bumping the Go version, don't forget to update the configuration of the
# CI jobs in openshift/release.
FROM registry.svc.ci.openshift.org/openshift/release:golang-1.14 AS builder
WORKDIR /go/src/github.com/openshift/cluster-monitoring-operator
COPY . .
ENV GOFLAGS="-mod=vendor"
RUN make operator-no-deps

FROM registry.svc.ci.openshift.org/openshift/origin-v4.0:base
LABEL io.k8s.display-name="OpenShift cluster-monitoring-operator" \
      io.k8s.description="This is a component of OpenShift and manages the lifecycle of the Prometheus based cluster monitoring stack." \
      io.openshift.tags="openshift" \
      io.openshift.release.operator=true \
      summary="This is a component of OpenShift and manages the lifecycle of the Prometheus based cluster monitoring stack." \
      maintainer="OpenShift Monitoring Team <team-monitoring@redhat.com>"

COPY --from=builder /go/src/github.com/openshift/cluster-monitoring-operator/operator /usr/bin/
COPY manifests /manifests
USER 1001
ENTRYPOINT ["/usr/bin/operator"]

