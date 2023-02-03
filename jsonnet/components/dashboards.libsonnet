local kubernetesGrafana = import 'github.com/brancz/kubernetes-grafana/grafana/grafana.libsonnet';
local grafana = import 'github.com/grafana/grafonnet-lib/grafonnet/grafana.libsonnet';

function(params)
  local cfg = params;

  // List of dashboards which should be shown in OCP developer perspective.
  local odcDashboards = [
    'grafana-dashboard-k8s-resources-namespace',
    'grafana-dashboard-k8s-resources-workloads-namespace',
    'grafana-dashboard-k8s-resources-pod',
    'grafana-dashboard-k8s-resources-workload',
  ];

  // index by: data[key] - row.title - panel.title
  local dashboardsToUnstack = {
    'k8s-resources-pod.json': {
      'CPU Usage': ['CPU Usage'],
      'Memory Usage': ['Memory Usage (WSS)'],
    },
    'k8s-resources-namespace.json': {
      'CPU Usage': ['CPU Usage'],
      'Memory Usage': ['Memory Usage (w/o cache)'],
    },
    'k8s-resources-node.json': {
      'CPU Usage': ['CPU Usage'],
      'Memory Usage': ['Memory Usage (w/o cache)'],
    },
    'k8s-resources-workload.json': {
      'CPU Usage': ['CPU Usage'],
      'Memory Usage': ['Memory Usage'],
    },
    'k8s-resources-workloads-namespace.json': {
      'CPU Usage': ['CPU Usage'],
      'Memory Usage': ['Memory Usage'],
    },
  };
  local shouldUnstack = function(filename, rowTitle, panelTitle)
    if std.objectHas(dashboardsToUnstack, filename) then
      local rowDict = dashboardsToUnstack[filename];
      if std.objectHas(rowDict, rowTitle) then
        local panelList = rowDict[rowTitle];
        if std.member(panelList, panelTitle) then
          true
        else
          false
      else
        false
    else
      false
  ;

  local nodeDashboards = [
    'k8s-resources-node.json',
    'node-rsrc-use.json',
  ];

  local glib = kubernetesGrafana(cfg) + {
    _config+: {
      clusterLabel: 'cluster',
    },
  };

  local unstackDashboards = function(dashboards)
    std.map(
      function(dashboard)
        local data = { [k]: std.parseJson(dashboard.data[k]) for k in std.objectFields(dashboard.data) };
        local updatedDashboard = dashboard {
          data: {
            [k]: data[k] {
              rows: std.map(function(row)
                row {
                  panels: std.map(function(panel)
                    if shouldUnstack(k, row.title, panel.title) then
                      panel {
                        stack: false,
                      }
                    else
                      panel, row.panels),
                }, data[k].rows),
            }
            for k in std.objectFields(data)
          },
        };
        updatedDashboard {
          data: { [k]: std.manifestJsonEx(updatedDashboard.data[k], '    ') for k in std.objectFields(updatedDashboard.data) },
        },
      dashboards
    );

  local addRoleTemplate = function(templateList)
    local template = grafana.template;
    std.flattenArrays([
      if std.member(['node', 'instance'], t.name) then
        [
          template.new(
            name='role',
            datasource='$datasource',
            query='label_values(kube_node_role{%(clusterLabel)s="$cluster"}, role)' % glib._config,
            allValues='.+',
            current='all',
            hide='',
            refresh=2,
            includeAll=true,
            sort=1
          ),
          template.new(
            name=t.name,
            datasource='$datasource',
            query='label_values(kube_node_info{%(clusterLabel)s="$cluster"} * on (node) group_right kube_node_role{%(clusterLabel)s="$cluster", role=~"$role"}, node)' % glib._config,
            current='',
            hide='',
            refresh=2,
            includeAll=false,
            multi=true,
            sort=1
          ),
        ]
      else
        [t]
      for t in templateList
    ]);

  local nodeRoleTemplate = function(dashboards)
    std.map(
      function(dashboard)
        local data = { [k]: std.parseJson(dashboard.data[k]) for k in std.objectFields(dashboard.data) };
        local updatedDashboard = dashboard {
          data: {
            [k]: if std.member(nodeDashboards, k) then
              data[k] {
                templating: {
                  list: addRoleTemplate(data[k].templating.list),
                },
              }
            else
              data[k]
            for k in std.objectFields(data)
          },
        };
        updatedDashboard {
          data: { [k]: std.manifestJsonEx(updatedDashboard.data[k], '    ') for k in std.objectFields(updatedDashboard.data) },
        },
      dashboards
    );

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
        // Openshift Console cannot show chart with both stacked and unstacked metrics,
        // so charts with metrics such as request/quota/limit show all metrics in
        // an unstacked way to avoid confusion.
        // please refer to: https://issues.redhat.com/browse/OCPBUGS-5353
        nodeRoleTemplate(unstackDashboards(glib.dashboardDefinitions.items)),
      ),
    },
  }
