# Update and compatibility guarantees

In order to be able to deliver updates with guaranteed compatibility, configurability of the Cluster Monitoring stack is limited to the explicitly available options. This document describes known pitfalls of which types of configuration and customization are unsupported, as well as misuse of resources provided by Cluster Monitoring. All configuration options described in [configuring Cluster Monitoring][configuring-monitoring] are explicitly supported. If there is the necessity to configure Cluster Monitoring further, please contact support in order for the team to add it as an explicit feature.

## Configuring Cluster Monitoring

The supported way of configuring Cluster Monitoring is by configuring it using, the options described in [configuring Cluster Monitoring][configure-monitoring]. Beyond those explicitly configuration options, it is possible to inject additional configuration into the stack, however this is unsupported, as configuration paradigms may change across Prometheus releases, and such cases can only be handled gracefully, if all configuration possibilities are controlled.

Explicitly unsupported cases include:

* Creating additional `ServiceMonitor` objects in the `openshift-monitoring` namespace, thereby extending the targets the cluster monitoring Prometheus instance scrapes. This can cause collisions and load differences that cannot be accounted for, therefore the Prometheus setup can be unstable.
* Creating additional `ConfigMap` objects, that cause the cluster monitoring Prometheus instance to include additional alerting and recording rules. Note that this behavior is known to cause a breaking behavior if applied, as Prometheus 2.0 will ship with a new rule file syntax.

## Using Cluster Monitoring created resources

Cluster Monitoring creates a number of resources. These resources are not meant to be used by any other resources, as there are no guarantees about their backward compatibility. For example, a `ClusterRole` called `prometheus-k8s` is created, and has very specific roles that exist solely for the cluster monitoring Prometheus pods to be able to access the resources it requires access to. All of these resources have no compatibility guarantees going forward. While some of these resources may incidentally have the necessary information for RBAC purposes for example, they can be subject to change in any upcoming release, with no backward compatibility.

If `Role`s or `ClusterRole`s that are similar are needed, we recommend creating a new object that has exactly the permissions required for the case at hand, rather than using the resources created and maintained by Cluster Monitoring.

[configure-monitoring]: configuring-cluster-monitoring.md
