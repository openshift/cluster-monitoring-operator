local grafana = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/grafana.libsonnet';

function(params)
  local cfg = params;

  // List of dashboards which should be shown in OCP developer perspective.
  local odcDashboards = [
    'grafana-dashboard-k8s-resources-namespace',
    'grafana-dashboard-k8s-resources-workloads-namespace',
    'grafana-dashboard-k8s-resources-pod',
    'grafana-dashboard-k8s-resources-workload',
  ];

  local glib = grafana(cfg) {};

  {
    consoleDashboardDefinitions: {
      apiVersion: 'v1',
      kind: 'ConfigMapList',
      items: std.filterMap(
        // etcd dashboard is deployed by cluster-etcd-operator
        // PR: https://github.com/openshift/cluster-etcd-operator/pull/837
        function(d) d.metadata.name != 'grafana-dashboard-etcd',
        function(d)
          d {
            metadata+: {
              namespace: 'openshift-config-managed',
              labels+: {
                'console.openshift.io/dashboard': 'true',
              } + if std.count(odcDashboards, d.metadata.name) > 0 then {
                'console.openshift.io/odc-dashboard': 'true',
              } else {},
            },
          },
        glib.dashboardDefinitions.items,
      ),
    },
  }
