FROM openshift/origin-base

ENV GOPATH /go
ENV PATH="${PATH}:${GOPATH}/bin"
RUN mkdir $GOPATH

COPY . $GOPATH/src/github.com/openshift/cluster-monitoring-operator
COPY manifests /manifests

RUN yum install -y golang make git && \
    cd $GOPATH/src/github.com/openshift/cluster-monitoring-operator && \
    make operator-no-deps && cp $GOPATH/src/github.com/openshift/cluster-monitoring-operator/operator /usr/bin/ && \
    yum erase -y golang make git && yum clean all

LABEL io.k8s.display-name="OpenShift cluster-monitoring-operator" \
      io.k8s.description="This is a component of OpenShift Container Platform and manages the lifecycle of the Prometheus based cluster monitoring stack." \
      io.openshift.tags="openshift" \
      io.openshift.release.operator=true \
      maintainer="Frederic Branczyk <fbranczy@redhat.com>"

# doesn't require a root user.
USER 1001

ENTRYPOINT ["/usr/bin/operator"]
