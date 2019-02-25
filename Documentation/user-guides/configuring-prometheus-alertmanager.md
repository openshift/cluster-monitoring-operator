# Configuring Prometheus Alertmanager

The Prometheus Alertmanager is a component that groups alerts, reliably deduplicates, and sends the grouped alerts as notifications.

Cluster Monitoring ships a central, highly available Alertmanager cluster. This cluster is meant to be used by all Prometheus instances, meaning all Prometheus instances will fire alerts against it, whenever an alerting rule is triggering.

## Editing the configuration

Use `kubectl get secret` to view the currently active Alertmanager configuration.

On Linux, run:

```bash
kubectl -n openshift-monitoring get secret alertmanager-main -ojson | jq -r '.data["alertmanager.yaml"]' | base64 -d
```

On macOS run:

```bash
kubectl -n openshift-monitoring get secret alertmanager-main -ojson | jq -r '.data["alertmanager.yaml"]' | base64 -D
```

To print to file, on Linux run:

```bash
kubectl -n openshift-monitoring get secret alertmanager-main -ojson | jq -r '.data["alertmanager.yaml"]' | base64 -d > alertmanager.yaml
```

On macOS run:

```bash
kubectl -n openshift-monitoring get secret alertmanager-main -ojson | jq -r '.data["alertmanager.yaml"]' | base64 -D > alertmanager.yaml
```

Once edited, apply the configuration:

```bash
kubectl -n openshift-monitoring create secret generic alertmanager-main --from-literal=alertmanager.yaml="$(< alertmanager.yaml)" --dry-run -oyaml | kubectl -n openshift-monitoring replace secret --filename=-
```

## Default configuration

The default configuration of the Cluster Monitoring Alertmanager cluster is:

[embedmd]:# (../../examples/config/alertmanager/default.yaml)
```yaml
global:
  resolve_timeout: 5m
route:
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 12h
  receiver: default
  routes:
  - match:
      alertname: DeadMansSwitch
    repeat_interval: 5m
    receiver: deadmansswitch
receivers:
- name: default
- name: deadmansswitch
```

This configuration contains a route for the alert named "DeadMansSwitch" by default.

### Dead man's switch

Cluster Monitoring ships with a "Dead man's switch" to ensure the availability of the monitoring infrastructure.

The "Dead man's switch" is a simple Prometheus alerting rule that always triggers. The Alertmanager continuously sends notifications for the dead man's switch to the notification provider that supports this functionality. This also ensures that communication between the Alertmanager and the notification provider is working.

This mechanism is supported by PagerDuty to issue alerts when the monitoring system itself is down. For more information, see [Dead man's switch PagerDuty](#dead-mans-switch-pagerduty) below.

## Grouping alerts

Once alerts are firing against the Alertmanager, it must be configured to know how to logically group them.

For this example a new route will be added to reflect alert routing of the "frontend" team.

> See [application monitoring][application-monitoring] for an example of the frontend application with alerting rules.

First, add new routes. Multiple routes may be added beneath the original route, typically to define the receiver for the notification. The following example uses a matcher to ensure that only alerts coming from the service `example-app` are used.

[embedmd]:# (../../examples/user-guides/configuring-prometheus-alertmanager/alertmanager-config-frontend-route.yaml)
```yaml
global:
  resolve_timeout: 5m
route:
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 12h
  receiver: default
  routes:
  - match:
      alertname: DeadMansSwitch
    repeat_interval: 5m
    receiver: deadmansswitch
  - match:
      service: example-app
    routes:
    - match:
        severity: critical
      receiver: team-frontend-page
receivers:
- name: default
- name: deadmansswitch
```

The sub-route matches only on alerts that have a severity of `critical`, and sends them via the receiver called `team-frontend-page`. As the name indicates, someone should be paged for alerts that are critical.

## Sending alerts to PagerDuty

The following example configures [PagerDuty][pagerduty] for notifications. See the PagerDuty documentation for [Alertmanager][pagerduty-alertmanager] to learn how to retrieve the `service_key`.

[embedmd]:# (../../examples/user-guides/configuring-prometheus-alertmanager/alertmanager-config-frontend-receiver.yaml)
```yaml
global:
  resolve_timeout: 5m
route:
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 12h
  receiver: default
  routes:
  - match:
      alertname: DeadMansSwitch
    repeat_interval: 5m
    receiver: deadmansswitch
  - match:
      service: example-app
    routes:
    - match:
        severity: critical
      receiver: team-frontend-page
receivers:
- name: default
- name: deadmansswitch
- name: team-frontend-page
  pagerduty_configs:
  - service_key: "<key>"
```

### Dead man's switch PagerDuty

[PagerDuty][pagerduty] supports this mechanism through an integration called [Dead Man's Snitch][deadman-snitch].  Once you have signed up for Dead Man's Snitch and created a snitch, set up a webhook to talk to its unique URL:

```yaml
global:
  resolve_timeout: 5m
route:
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 12h
  receiver: default
  routes:
  - match:
      alertname: DeadMansSwitch
    repeat_interval: 5m
    receiver: deadmansswitch
receivers:
- name: default
  pagerduty_configs:
  - service_key: "XXXXXX"
- name: deadmansswitch
  webhook_configs:
    - url: "https://nosnch.in/XXXXXX
```

Configure a Dead Man's Snitch integration with PagerDuty, along with an escalation on PagerDuty to page the operator if the Dead man's switch alert is silent for 15 minutes. With the default Alertmanager configuration, the Dead man's switch alert is repeated every five minutes. If Dead Man's Snitch triggers after 15 minutes, it indicates that the notification has been unsuccessful at least twice.

Learn how to [configure Dead Man's Snitch for PagerDuty][configure-snitch].

## Sending alerts to email

Configure the route's `receiver` to issue alerts by email.

For example:

```yaml
receivers:
- name: email_config
  email_configs:
  - to: 'admin@example.com'
    from: 'admin@example.com'
    smarthost: 'smtp.example.com:587'
    auth_username: 'admin@example.com'
    auth_password: '<email_password_or_token>'
    auth_secret: 'admin@example.com'
    auth_identity: 'admin@example.com'
```

For more information, see [email_config][email-config] in the Prometheus Configuration options documentation.


[pagerduty]: https://www.pagerduty.com/
[pagerduty-alertmanager]: https://www.pagerduty.com/docs/guides/prometheus-integration-guide/
[deadman-snitch]: https://deadmanssnitch.com/
[configure-snitch]: https://www.pagerduty.com/docs/guides/dead-mans-snitch-integration-guide/
[application-monitoring]: application-monitoring.md
[email-config]: https://prometheus.io/docs/alerting/configuration/#email_config
