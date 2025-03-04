local tmpVolumeName = 'volume-directive-shadow';
local tlsVolumeName = 'kube-state-metrics-tls';
local crsVolumeName = 'kube-state-metrics-custom-resource-state-configmap';

local kubeStateMetrics = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/kube-state-metrics.libsonnet';
local kubeStateMetricsCRS = import '../utils/kube-state-metrics-custom-resource-state.libsonnet';
local generateSecret = import '../utils/generate-secret.libsonnet';
local generateServiceMonitor = import '../utils/generate-service-monitors.libsonnet';
local withDescription = (import '../utils/add-annotations.libsonnet').withDescription;

function(params)
  local cfg = params;
  local crsConfig = {
    apiVersion: 'v1',
    kind: 'ConfigMap',
    metadata: {
      name: 'kube-state-metrics-custom-resource-state-configmap',
      namespace: 'openshift-monitoring',
    },
    data: {
      'custom-resource-state-configmap.yaml': std.manifestYamlDoc(kubeStateMetricsCRS.Config()),
    },
  };

  kubeStateMetrics(cfg) + {
    // Adding the serving certs annotation causes the serving certs controller
    // to generate a valid and signed serving certificate and put it in the
    // specified secret.
    service+: {
      metadata+: {
        annotations+: {
          'service.beta.openshift.io/serving-cert-secret-name': 'kube-state-metrics-tls',
        } + withDescription(
          |||
            Expose kube-state-metrics `/metrics` endpoints within the cluster on the following ports:
            * Port %d provides access to the Kubernetes resource metrics. This port is for internal use, and no other usage is guaranteed.
            * Port %d provides access to the internal kube-state-metrics metrics. This port is for internal use, and no other usage is guaranteed.
          ||| % [$.service.spec.ports[0].port, $.service.spec.ports[1].port],
        ),
      },
    },

    clusterRole+: {
      rules+: [
        {
          apiGroups: ['autoscaling.k8s.io'],
          resources: ['verticalpodautoscalers'],
          verbs: ['list', 'watch'],
        },
        // CRD read permissions are required for kube-state-metrics to support the CRS feature-set.
        // Refer: https://github.com/kubernetes/kube-state-metrics/pull/1851/files#diff-916e6863e1245c673b4e5965c98dc27bafbd72650fdb38ce65ea73ee6304e027R45-R47
        {
          apiGroups: ['apiextensions.k8s.io'],
          resources: ['customresourcedefinitions'],
          verbs: ['get', 'list', 'watch'],
        },
      ],
    },

    // This changes kube-state-metrics to be scraped with validating TLS.

    serviceMonitor+: {
      metadata+: {
        name: super.name,
        labels+: {
          'monitoring.openshift.io/collection-profile': 'full',
        },
      },
      spec+: {
        endpoints: [
          {
            honorLabels: true,
            interval: '1m',
            scrapeTimeout: '1m',
            port: 'https-main',
            scheme: 'https',
            // Drop the "instance" and "pod" labels since we're runinng only
            // one instance of kube-state-metrics. The "instance" label must be
            // dropped at the metrics relabeling stage (instead of the service
            // discovery stage) because otherwise Prometheus will default its
            // value to the address being scraped.
            // The net result is to avoid excessive series churn when
            // kube-state-metrics is redeployed because of node reboot, pod
            // rescheduling or cluster upgrade.
            metricRelabelings: [
              {
                action: 'labeldrop',
                regex: 'instance',
              },
            ],
            relabelings: [
              {
                action: 'labeldrop',
                regex: 'pod',
              },
            ],
          },
          {
            interval: '1m',
            scrapeTimeout: '1m',
            port: 'https-self',
            scheme: 'https',
          },
        ],
      },
    },

    minimalServiceMonitor: generateServiceMonitor.minimal(
      self.serviceMonitor, std.join('|',
                                    [
                                      'kube_daemonset_status_current_number_scheduled',
                                      'kube_daemonset_status_desired_number_scheduled',
                                      'kube_daemonset_status_number_available',
                                      'kube_daemonset_status_number_misscheduled',
                                      'kube_daemonset_status_updated_number_scheduled',
                                      'kube_deployment_metadata_generation',
                                      'kube_deployment_spec_replicas',
                                      'kube_deployment_status_observed_generation',
                                      'kube_deployment_status_replicas_available',
                                      'kube_deployment_status_replicas_updated',
                                      'kube_horizontalpodautoscaler_spec_max_replicas',
                                      'kube_horizontalpodautoscaler_spec_min_replicas',
                                      'kube_horizontalpodautoscaler_status_current_replicas',
                                      'kube_horizontalpodautoscaler_status_desired_replicas',
                                      'kube_job_failed',
                                      'kube_job_status_active',
                                      'kube_job_status_start_time',
                                      'kube_node_info',
                                      'kube_node_labels',
                                      'kube_node_role',
                                      'kube_node_spec_taint',
                                      'kube_node_spec_unschedulable',
                                      'kube_node_status_allocatable',
                                      'kube_node_status_capacity',
                                      'kube_node_status_condition',
                                      'kube_persistentvolume_info',
                                      'kube_persistentvolume_status_phase',
                                      'kube_persistentvolumeclaim_access_mode',
                                      'kube_persistentvolumeclaim_info',
                                      'kube_persistentvolumeclaim_labels',
                                      'kube_persistentvolumeclaim_resource_requests_storage_bytes',
                                      'kube_pod_container_resource_limits',
                                      'kube_pod_container_resource_requests',
                                      'kube_pod_container_status_last_terminated_reason',
                                      'kube_pod_container_status_restarts_total',
                                      'kube_pod_container_status_waiting_reason',
                                      'kube_pod_info',
                                      'kube_pod_owner',
                                      'kube_pod_status_phase',
                                      'kube_pod_status_ready',
                                      'kube_pod_status_unschedulable',
                                      'kube_poddisruptionbudget_status_current_healthy',
                                      'kube_poddisruptionbudget_status_desired_healthy',
                                      'kube_poddisruptionbudget_status_expected_pods',
                                      'kube_replicaset_owner',
                                      'kube_replicationcontroller_owner',
                                      'kube_resourcequota',
                                      'kube_state_metrics_list_total',
                                      'kube_state_metrics_watch_total',
                                      'kube_statefulset_metadata_generation',
                                      'kube_statefulset_replicas',
                                      'kube_statefulset_status_current_revision',
                                      'kube_statefulset_status_observed_generation',
                                      'kube_statefulset_status_replicas',
                                      'kube_statefulset_status_replicas_ready',
                                      'kube_statefulset_status_replicas_updated',
                                      'kube_statefulset_status_update_revision',
                                      'kube_storageclass_info',
                                      'process_start_time_seconds',
                                    ])
    ),

    kubeRbacProxySecret: generateSecret.staticAuthSecret(cfg.namespace, cfg.commonLabels, 'kube-state-metrics-kube-rbac-proxy-config'),

    // This removes the upstream addon-resizer and all resource requests and
    // limits. Additionally configures the kube-rbac-proxies to use the serving
    // cert configured on the `Service` above.
    //
    // The upstream kube-state-metrics Dockerfile defines a `VOLUME` directive
    // in `/tmp`. Although this is unused it will take some time for it to get
    // released, which is why it is shadowed here for the time being.

    deployment+: {
      metadata+: {
        labels+: {
          'app.kubernetes.io/managed-by': 'cluster-monitoring-operator',
        },
      },
      spec+: {
        template+: {
          metadata+: {
            labels+: {
              'app.kubernetes.io/managed-by': 'cluster-monitoring-operator',
            },
            annotations+: {
              'openshift.io/required-scc': 'restricted-v2',
            },
          },
          spec+: {
            containers:
              std.filterMap(
                function(c) c.name != 'addon-resizer',
                function(c)
                  if std.startsWith(c.name, 'kube-rbac-proxy') then
                    c {
                      args+: [
                        '--tls-cert-file=/etc/tls/private/tls.crt',
                        '--tls-private-key-file=/etc/tls/private/tls.key',
                        '--client-ca-file=/etc/tls/client/client-ca.crt',
                        '--config-file=/etc/kube-rbac-policy/config.yaml',
                      ],
                      volumeMounts: [
                        {
                          mountPath: '/etc/tls/private',
                          name: tlsVolumeName,
                          readOnly: false,
                        },
                        {
                          mountPath: '/etc/tls/client',
                          name: 'metrics-client-ca',
                          readOnly: false,
                        },
                        {
                          mountPath: '/etc/kube-rbac-policy',
                          name: 'kube-state-metrics-kube-rbac-proxy-config',
                          readOnly: true,
                        },
                      ],
                      securityContext: {},
                      resources: {
                        requests: {
                          memory: '15Mi',
                          cpu: '1m',
                        },
                      },
                    }
                  else
                    c {
                      args+: [
                        |||
                          --metric-denylist=
                          ^kube_secret_labels$,
                          ^kube_.+_annotations$
                          ^kube_customresource_.+_annotations_info$,
                          ^kube_customresource_.+_labels_info$,
                        |||,
                        '--metric-labels-allowlist=pods=[*],nodes=[*],namespaces=[*],persistentvolumes=[*],persistentvolumeclaims=[*],poddisruptionbudgets=[*],jobs=[*],cronjobs=[*]',
                      ],
                      securityContext: {},
                      resources: {
                        requests: {
                          memory: '80Mi',
                          cpu: '2m',
                        },
                      },
                      volumeMounts: [
                        {
                          mountPath: '/tmp',
                          name: tmpVolumeName,
                          readOnly: false,
                        },
                        // The custom resource state configmap is always mounted in the kube-state-metrics container and only when the VPA CRD is installed, CMO will add `--custom-resource-state-config-file` to the container arguments list.
                        {
                          mountPath: '/etc/kube-state-metrics',
                          name: crsVolumeName,
                          readOnly: true,
                        },
                      ],
                    },
                super.containers,
              ),
            volumes+: [
              {
                emptyDir: {},
                name: tmpVolumeName,
              },
              {
                name: tlsVolumeName,
                secret: {
                  secretName: 'kube-state-metrics-tls',
                },
              },
              {
                name: 'metrics-client-ca',
                configMap: {
                  name: 'metrics-client-ca',
                },
              },
              {
                name: 'kube-state-metrics-kube-rbac-proxy-config',
                secret: {
                  secretName: 'kube-state-metrics-kube-rbac-proxy-config',
                },
              },
              {
                name: crsVolumeName,
                configMap: {
                  name: crsVolumeName,
                },
              },
            ],
            securityContext: {},
            priorityClassName: 'system-cluster-critical',
          },
        },
      },
    },

    customResourceStateConfigmap: crsConfig,
  }
