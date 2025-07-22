# Debug Container for Cluster Monitoring Operator

## Overview

The Cluster Monitoring Operator (CMO) supports an optional debug container that can be deployed as a sidecar alongside the main operator. This debug container provides additional tooling capabilities for troubleshooting monitoring stack issues without requiring separate pod deployments or complex debugging setups.

## Enabling the Debug Container

### For Existing Clusters (Immediate Use)

Create a patch file to add the debug container to the running deployment:

```bash
# Create debug container patch
cat > debug-enable-patch.yaml << 'EOF'
spec:
  template:
    spec:
      containers:
      - name: debug-tools
        image: registry.redhat.io/ubi9/ubi:latest
        command: ["/bin/bash", "-c", "dnf swap -y libcurl-minimal libcurl && sleep infinity"]
        resources:
          requests:
            cpu: 10m
            memory: 32Mi
          limits:
            cpu: 50m
            memory: 128Mi
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
          runAsNonRoot: true
        terminationMessagePolicy: FallbackToLogsOnError
EOF

# Apply the patch
kubectl patch deployment cluster-monitoring-operator \
  -n openshift-monitoring \
  --patch-file debug-enable-patch.yaml

# Verify the rollout
kubectl rollout status deployment/cluster-monitoring-operator -n openshift-monitoring
```

### Option 2: Edit Deployment Directly

```bash
# Edit the deployment manifest
kubectl edit deployment cluster-monitoring-operator -n openshift-monitoring

# Find the commented debug container section and uncomment it:
# Look for the section starting with "# DEBUG TOOLS SIDECAR (OPTIONAL)"
# Remove the '#' from the container definition lines
```

## Using the Debug Container

### Basic Access

Once enabled, access the debug container using kubectl exec:

```bash
# Access the debug container
kubectl exec -n openshift-monitoring \
  deployment/cluster-monitoring-operator \
  -c debug-tools -- /bin/bash

# Or target a specific pod
kubectl exec -n openshift-monitoring \
  pod/cluster-monitoring-operator-xyz \
  -c debug-tools -- /bin/bash
```

## Common Use Cases and Examples

### 1. Network Connectivity Testing

```bash
# Exec into debug container
kubectl exec -n openshift-monitoring deployment/cluster-monitoring-operator -c debug-tools -- /bin/bash

# Test connectivity to Prometheus
curl -I http://prometheus-k8s.openshift-monitoring:9090/metrics

# Test connectivity to Alertmanager
curl -I http://alertmanager-main.openshift-monitoring:9093/api/v1/status

# DNS resolution testing
nslookup prometheus-k8s.openshift-monitoring
nslookup alertmanager-main.openshift-monitoring

# Network port testing (if netcat is available)
nc -zv prometheus-k8s.openshift-monitoring 9090
```

### 2. Kubernetes API Debugging

```bash
# Use the mounted service account token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CA_CERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Test API access with same permissions as operator
curl -H "Authorization: Bearer $TOKEN" \
  --cacert $CA_CERT \
  https://kubernetes.default.svc/api/v1/namespaces/openshift-monitoring/pods

# Check RBAC permissions
curl -H "Authorization: Bearer $TOKEN" \
  --cacert $CA_CERT \
  https://kubernetes.default.svc/apis/authorization.k8s.io/v1/selfsubjectaccessreviews \
  -X POST -H "Content-Type: application/json" -d '{
    "kind": "SelfSubjectAccessReview",
    "apiVersion": "authorization.k8s.io/v1",
    "spec": {
      "resourceAttributes": {
        "namespace": "openshift-monitoring",
        "verb": "get",
        "resource": "pods"
      }
    }
  }'
```

### 3. Resource and Environment Investigation

```bash
# Check process information
ps aux

# Monitor resource usage
top

# Check mounted volumes
mount | grep -E "(configmap|secret)"

# Examine environment variables
env | sort

# Check disk usage
df -h

# Network interface information
ip addr show

# Process network connections
ss -tuln
```

### 4. Configuration Analysis

```bash
# Examine mounted ConfigMaps
find /etc -name "*.yaml" -o -name "*.yml" | head -10
cat /etc/cluster-monitoring-operator/telemetry/metrics.yaml

# Check mounted secrets
ls -la /etc/ssl/certs/
ls -la /var/run/secrets/

# Validate configuration files
find /etc -type f -exec file {} \; | grep -i yaml
```

### 5. Log Analysis

```bash
# Check operator logs from inside the pod
# (Note: This shows logs from the main container, not the debug container)
tail -f /proc/1/fd/1

# Or check specific log files if they exist
find /var/log -type f 2>/dev/null
```

## Custom Debug Images

For enhanced debugging capabilities, you can create a custom debug image with additional tools:

### Creating a Custom Debug Image

```dockerfile
# Example Dockerfile for custom debug image
FROM registry.redhat.io/ubi9/ubi:latest

# Install common debugging tools and swap to full curl
RUN dnf update -y && \
    dnf swap -y libcurl-minimal libcurl && \
    dnf install -y \
    wget \
    bind-utils \
    procps-ng \
    && dnf clean all

USER 1001
CMD ["/bin/sleep", "infinity"]
```

### Using a Custom Image

Update the image reference in your debug container patch:

```yaml
spec:
  template:
    spec:
      containers:
      - name: debug-tools
        image: quay.io/your-org/debug-tools:latest  # Your custom image
        command: ["/bin/sleep", "infinity"]
        # ... rest of container spec
```

## Security Considerations

The debug container runs with a restricted security context:

- **No privilege escalation** - `allowPrivilegeEscalation: false`
- **Dropped capabilities** - All Linux capabilities are dropped
- **Non-root user** - Runs as non-root user (UID 1001)
- **Same permissions** - Uses the same ServiceAccount as the operator
- **Network isolation** - Shares the pod network namespace

## Troubleshooting

### Debug Container Won't Start

```bash
# Check pod events
kubectl describe pod -n openshift-monitoring -l app.kubernetes.io/name=cluster-monitoring-operator

# Check container status
kubectl get pods -n openshift-monitoring -l app.kubernetes.io/name=cluster-monitoring-operator -o jsonpath='{.items[0].status.containerStatuses}'

# Verify image pull
kubectl get events -n openshift-monitoring --field-selector reason=Failed
```

### Cannot Access Debug Container

```bash
# Verify container is running
kubectl get pods -n openshift-monitoring -l app.kubernetes.io/name=cluster-monitoring-operator

# Check if debug container exists
kubectl get pods -n openshift-monitoring -l app.kubernetes.io/name=cluster-monitoring-operator -o jsonpath='{.items[0].spec.containers[*].name}'

# Try accessing by pod name instead of deployment
kubectl get pods -n openshift-monitoring -l app.kubernetes.io/name=cluster-monitoring-operator
kubectl exec -n openshift-monitoring pod/cluster-monitoring-operator-abc123 -c debug-tools -- /bin/bash
```
