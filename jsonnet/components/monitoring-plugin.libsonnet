function(params)
  local cfg = params;

  local pluginName = 'monitoring-plugin';
  local pluginLabels = {
    'app.kubernetes.io/name': pluginName,
    'app.kubernetes.io/component': pluginName,
    'app.kubernetes.io/managed-by': 'cluster-monitoring-operator',
  } + cfg.commonLabels;

  local nginxPort = 9443;
  local nginxPortName = 'https';

  local tlsSecret = 'monitoring-plugin-cert';
  local tlsVolumeName = 'monitoring-plugin-cert';
  local tlsMountPath = '/var/cert';
  local nginxConf = |||
    error_log /dev/stdout info;
    events {}
    http {
      include            /etc/nginx/mime.types;
      default_type       application/octet-stream;
      keepalive_timeout  65;
      server {
        listen              %(nginxPort)d ssl;
        ssl_certificate     %(tlsPath)s/tls.crt;
        ssl_certificate_key %(tlsPath)s/tls.key;
        root                /usr/share/nginx/html;
      }
    }
  ||| % { tlsPath: tlsMountPath, nginxPort: nginxPort };

  local nginxConfigMap = pluginName;
  local nginxCMVolName = 'nginx-conf';
  local nginxConfMountPath = '/etc/nginx/nginx.conf';


  {
    _config+:: {
      name: pluginName,
      namespace: 'openshift-monitoring',

      // NOTE: using pluginLabels ensures that both common and plugin labels
      // are merged and allows all resources to just use $._config.labels
      labels+:: pluginLabels,

      image: 'IMAGE NOT SPECIFIED',
    } + cfg,

    // utility functions

    metadata(noName=false, noNamespace=false)::
      local name = if noName then {} else { name: $._config.name };
      local ns = if noNamespace then {} else { namespace: $._config.namespace };
      { labels: $._config.labels } + name + ns,

    configmapVolume(volName, cmName):: {
      name: volName,
      configMap: {
        name: cmName,
        defaultMode: 420,
      },
    },

    volumeMount(name, path, subPath=''):: {
      name: name,
      mountPath: path,
      readOnly: true,
    } + if subPath == '' then {}
    else { subPath: subPath },  // add sub-path if specified

    configMapVolume(name, cmName):: {
      name: name,
      configMap: {
        defaultMode: 420,
        name: cmName,
      },
    },

    secretVolume(name, secretName):: {
      name: name,
      secret: {
        defaultMode: 420,
        secretName: secretName,
      },
    },

    // resources
    configMap: {
      apiVersion: 'v1',
      kind: 'ConfigMap',
      metadata: $.metadata(),
      data: {
        'nginx.conf': nginxConf,
      },
    },

    consolePlugin: {
      apiVersion: 'console.openshift.io/v1',
      kind: 'ConsolePlugin',
      metadata: $.metadata(noNamespace=true),
      spec: {
        displayName: $._config.name,
        backend: {
          type: 'Service',
          service: {
            basePath: '/',
            name: $._config.name,
            namespace: $._config.namespace,
            port: nginxPort,
          },
        },
      },
    },


    podDisruptionBudget: {
      apiVersion: 'policy/v1',
      kind: 'PodDisruptionBudget',
      metadata: $.metadata(),
      spec: {
        minAvailable: 1,
        selector: {
          matchLabels: $._config.labels,
        },

      },
    },

    serviceAccount: {
      apiVersion: 'v1',
      kind: 'ServiceAccount',
      metadata: $.metadata(),
    },

    servicePort(name, port, targetPort):: {
      name: name,
      port: port,
      targetPort: targetPort,
    },

    service: {
      apiVersion: 'v1',
      kind: 'Service',
      metadata: $.metadata() + {
        annotations: {
          'service.beta.openshift.io/serving-cert-secret-name': tlsSecret,
        },
      },
      spec: {
        ports: [$.servicePort('https', 9443, 'https')],
        selector: $._config.labels,
        sessionAffinity: 'None',
      },
    },

    deployment: {
      apiVersion: 'apps/v1',
      kind: 'Deployment',
      metadata: $.metadata(),
      spec: {
        replicas: 2,
        selector: {
          matchLabels: $._config.labels,

        },
        strategy: {
          rollingUpdate: { maxUnavailable: 1 },
          type: 'RollingUpdate',
        },
        template: {

          metadata: $.metadata(noName=true, noNamespace=true) + {
            annotations: {
              'target.workload.openshift.io/management': '{"effect": "PreferredDuringScheduling"}',
            },
          },
          spec: {
            affinity: {
              podAntiAffinity: {

                requiredDuringSchedulingIgnoredDuringExecution: [{

                  labelSelector: { matchLabels: $._config.labels },

                  namespaces: [$._config.namespace],
                  topologyKey: 'kubernetes.io/hostname',
                }],  // requiredDuringSchedulingIgnoredDuringExecution

              },  // podAntiAffinity
            },  // affinity
            automountServiceAccountToken: false,
            containers: [
              {  // monitoring-plugin container
                name: $._config.name,
                image: $._config.image,
                imagePullPolicy: 'IfNotPresent',
                ports: [
                  { containerPort: nginxPort, name: nginxPortName },
                ],
                resources: {
                  requests: { cpu: '10m', memory: '50Mi' },
                },
                securityContext: {
                  allowPrivilegeEscalation: false,
                  capabilities: {
                    drop: ['ALL'],
                  },
                },
                volumeMounts: [
                  $.volumeMount(tlsVolumeName, tlsMountPath),
                  $.volumeMount(nginxCMVolName, nginxConfMountPath, 'nginx.conf'),
                ],


              },  // monitoring-plugin container
            ],  // containers

            dnsPolicy: 'ClusterFirst',
            nodeSelector: { 'kubernetes.io/os': 'linux' },
            priorityClassName: 'system-cluster-critical',
            restartPolicy: 'Always',
            securityContext: {
              runAsNonRoot: true,
              seccompProfile: { type: 'RuntimeDefault' },
            },
            volumes: [
              $.configMapVolume(nginxCMVolName, nginxConfigMap),
              $.secretVolume(tlsVolumeName, tlsSecret),
            ],
          },  // spec
        },  // template
      },  // spec
    },  // deployment
  }
