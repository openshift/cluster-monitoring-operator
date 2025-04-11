local getCommonLabels(resourceType) =
  if resourceType != '' then {
    resource: resourceType,
    unit: if resourceType == 'cpu' then 'cores'
    else
      if resourceType == 'memory' then 'bytes',
  };

local vpaMetric(name, help, type, statesetScope='') = if name == '' || help == '' || type == '' then null else {
  local nameParts = std.split(name, '_'),
  local le = std.length(nameParts),
  local resourceType = if nameParts[le - 1] == 'cpu' then 'cpu' else if nameParts[le - 1] == 'memory' then 'memory' else '',
  local lastTwo = if nameParts[le - 1] == type then nameParts[le - 3:le - 1] else nameParts[le - 2:le],
  local noncamelcasedField = lastTwo[0],
  local camelcasedFields = {
    lowerbound: 'lowerBound',
    upperbound: 'upperBound',
    uncappedtarget: 'uncappedTarget',
    minallowed: 'minAllowed',
    maxallowed: 'maxAllowed',
  },
  local camelcasedField = if noncamelcasedField in camelcasedFields then camelcasedFields[noncamelcasedField] else noncamelcasedField,
  // 1 is the default for resolvedValueFrom
  local resolvedValueFrom = if resourceType == '' then 1
  else
    [camelcasedField, lastTwo[1]],
  local includeAllFields = {
    annotations: ['metadata', 'annotations'],
    labels: ['metadata', 'labels'],
  },
  local commonLabelsFromPath = {
    namespace: ['metadata', 'namespace'],
    verticalpodautoscaler: ['metadata', 'name'],
    target_api_version: ['spec', 'targetRef', 'apiVersion'],
    target_kind: ['spec', 'targetRef', 'kind'],
    target_name: ['spec', 'targetRef', 'name'],
  },
  local shortPathMaps = {
    containerrecommendations: ['status', 'recommendation', 'containerRecommendations'],
    container_policies: ['spec', 'resourcePolicy', 'containerPolicies'],
    updatemode: ['spec', 'updatePolicy', 'updateMode'],
  },
  local shortPathMatches = [shortPathMaps[s] for s in std.objectFields(shortPathMaps) if std.length(std.findSubstr(s, name)) > 0],
  local label = if nameParts[std.length(nameParts) - 1] == type then nameParts[std.length(nameParts) - 2] else nameParts[std.length(nameParts) - 1],

  // spec.resources[*].groupVersionKind[*].metrics[*] (kube-state-metrics >=v2.5.0)
  name: name,
  help: help,
  commonLabels: getCommonLabels(resourceType),
  each: {
    type: std.asciiUpper(type[0]) + type[1:],
    [type]: {
      [if std.length(shortPathMatches) > 1 then error 'expected 1 path match got ' + std.length(shortPathMatches) else if std.length(shortPathMatches) == 1 then 'path']: shortPathMatches[0],
      // StateSets do not support internal labelsFromPath.
      [if type != 'stateSet' then 'labelsFromPath']: {
        container: ['containerName'],
        [if std.objectHas(includeAllFields, lastTwo[1]) then '*']: includeAllFields[lastTwo[1]],
      },
      // labelName is only used by StateSets.
      [if type == 'stateSet' then 'labelName']: label,
      // list is only used by StateSets.
      [if type == 'stateSet' && statesetScope != null then 'list']: statesetScope,
      // valueFrom is only used by non-StateSets.
      [if type != 'stateSet' then 'valueFrom']: resolvedValueFrom,
    },
  },
  labelsFromPath: commonLabelsFromPath,
};

local vpaMetrics = [
  //  vpaMetric('verticalpodautoscaler_annotations_info', 'Kubernetes annotations converted to Prometheus labels.', 'info'),
  //  vpaMetric('verticalpodautoscaler_labels_info', 'Kubernetes labels converted to Prometheus labels.', 'info'),
  vpaMetric('verticalpodautoscaler_spec_updatepolicy_updatemode', 'Update mode of the VerticalPodAutoscaler.', 'stateSet', ['Off', 'Initial', 'Recreate', 'Auto']),
  vpaMetric('verticalpodautoscaler_status_recommendation_containerrecommendations_lowerbound_cpu', 'Minimum cpu resources the container can use before the VerticalPodAutoscaler updater evicts it.', 'gauge'),
  vpaMetric('verticalpodautoscaler_status_recommendation_containerrecommendations_lowerbound_memory', 'Minimum memory resources the container can use before the VerticalPodAutoscaler updater evicts it.', 'gauge'),
  vpaMetric('verticalpodautoscaler_status_recommendation_containerrecommendations_upperbound_cpu', 'Maximum cpu resources the container can use before the VerticalPodAutoscaler updater evicts it.', 'gauge'),
  vpaMetric('verticalpodautoscaler_status_recommendation_containerrecommendations_upperbound_memory', 'Maximum memory resources the container can use before the VerticalPodAutoscaler updater evicts it.', 'gauge'),
  vpaMetric('verticalpodautoscaler_status_recommendation_containerrecommendations_target_cpu', 'Target cpu resources the VerticalPodAutoscaler recommends for the container.', 'gauge'),
  vpaMetric('verticalpodautoscaler_status_recommendation_containerrecommendations_target_memory', 'Target memory resources the VerticalPodAutoscaler recommends for the container.', 'gauge'),
  vpaMetric('verticalpodautoscaler_status_recommendation_containerrecommendations_uncappedtarget_cpu', 'Target cpu resources the VerticalPodAutoscaler recommends for the container ignoring bounds.', 'gauge'),
  vpaMetric('verticalpodautoscaler_status_recommendation_containerrecommendations_uncappedtarget_memory', 'Target memory resources the VerticalPodAutoscaler recommends for the container ignoring bounds.', 'gauge'),
  vpaMetric('verticalpodautoscaler_spec_resourcepolicy_container_policies_minallowed_cpu', 'Minimum cpu resources the VerticalPodAutoscaler can set for containers matching the name.', 'gauge'),
  vpaMetric('verticalpodautoscaler_spec_resourcepolicy_container_policies_minallowed_memory', 'Minimum memory resources the VerticalPodAutoscaler can set for containers matching the name.', 'gauge'),
  vpaMetric('verticalpodautoscaler_spec_resourcepolicy_container_policies_maxallowed_cpu', 'Minimum cpu resources the VerticalPodAutoscaler can set for containers matching the name.', 'gauge'),
  vpaMetric('verticalpodautoscaler_spec_resourcepolicy_container_policies_maxallowed_memory', 'Minimum memory resources the VerticalPodAutoscaler can set for containers matching the name.', 'gauge'),
];

local gatewayClassMetrics = [
  {
    name: 'gateway_class',
    help: 'Information about GatewayClasses',
    each: {
      type: 'Info',
      info: {
        labelsFromPath: {
          namespace: ['metadata', 'namespace'],
          gateway_class: ['metadata', 'name'],
          controller_name: ['spec', 'controllerName'],
          accepted: ['status', 'conditions', '[type=Accepted]', 'status'],
          reason: ['status', 'conditions', '[type=Accepted]', 'reason']
        }
      }
    }
  },
];

local gatewayMetrics = [
  {
    name: 'gateway',
    help: 'Information about Gateways',
    each: {
      type: 'Info',
      info: {
        labelsFromPath: {
          namespace: ['metadata', 'namespace'],
          gateway: ['metadata', 'name'],
          gateway_class_name: ['spec', 'gatewayClassName'],
          programmed: ['status', 'conditions', '[type=Programmed]', 'status'],
          reason: ['status', 'conditions', '[type=Programmed]', 'reason']
        }
      }
    }
  },
];

local crsConfig = {
  kind: 'CustomResourceStateMetrics',
  spec: {
    resources: [
      {
        groupVersionKind: {
          group: 'autoscaling.k8s.io',
          version: 'v1',
          kind: 'VerticalPodAutoscaler',
        },
        metrics: vpaMetrics,
      },
      {
        groupVersionKind: {
          group: 'gateway.networking.k8s.io',
          version: 'v1',
          kind: 'GatewayClass',
        },
        metrics: gatewayClassMetrics,
      },
      {
        groupVersionKind: {
          group: 'gateway.networking.k8s.io',
          version: 'v1',
          kind: 'Gateway',
        },
        metrics: gatewayMetrics,
      },
    ],
  },
};

{
  Config():: crsConfig,
}
