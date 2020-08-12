#!/bin/bash
#
#*******************************************************************************
#  NOTE THAT THIS SCRIPT IS INTENDED FOR OPENSHIFT CONTAINER PLATFORM 4.6 (OR
#  LATER) TEST ENVIRONMENTS ONLY. THE SCRIPT MAKES CHANGES TO OAUTH IDENTITY
# PROVIDER CONFIGURATION, OPENSHIFT USER ACCOUNTS AND USER WORKLOAD MONITORING
#CONFIGURATION. THE SCRIPT ALSO DEPLOYS A USER APPLICATION IN A NAMESPACE CALLED
#  'ns1'. REVIEW THIS SCRIPT THOROUGHLY TO DETERMINE SUITABILITY FOR YOUR TEST
#                                  ENVIRONMENT
#*******************************************************************************
#
# This script automates user workload monitoring setup for newly deployed OpenShift Container Platform 4.6 (or later) test clusters.The script does the following:
#
# * Enables user workload monitoring
# * Deploys a user application
# * Configures HTPasswd identity provider, creates a secret and creates some users
# * Applies roles to those users
# * Adds a service monitor
# * Creates an alerting rule
# * Outputs cluster and Thanos URLs to stdout
#
# The script assumes that YAML files `./uwm_setup_files/example-app-alerting-rule.yaml`, `./uwm_setup_files/example-app-service-monitor.yaml` and `./uwm_setup_files/prometheus-example-app.yaml` are present in the current working directory along with the script itself.

TMP=$(mktemp -d)

function notice ()
{
echo "*******************************************************************************
  NOTE THAT THIS SCRIPT IS INTENDED FOR OPENSHIFT CONTAINER PLATFORM 4.6 (OR
  LATER) TEST ENVIRONMENTS ONLY. THE SCRIPT MAKES CHANGES TO OAUTH IDENTITY
 PROVIDER CONFIGURATION, OPENSHIFT USER ACCOUNTS AND USER WORKLOAD MONITORING
CONFIGURATION. THE SCRIPT ALSO DEPLOYS A USER APPLICATION IN A NAMESPACE CALLED
  'ns1'. REVIEW THIS SCRIPT THOROUGHLY TO DETERMINE SUITABILITY FOR YOUR TEST
                                  ENVIRONMENT
*******************************************************************************"
while true; do
  read -rp "Do you want to continue? (y/n): " YESNO
  case $YESNO in
      y ) break;;
      n ) echo "Exiting."; exit 0;;
      * ) echo "Please answer 'y' or 'n':";;
  esac
done
echo
}

function kubeadmin_login ()
{
echo "Log into your cluster initially as kubeadmin:"; echo

# Request cluster API endpoint and kubeadmin token from user:
read -rp "- Enter cluster API endpoint and port (i.e. https://api.<cluster_name>.<sub_domain>.<domain>:<port>: " APIURL
echo
unset -v KUBEPW # Make sure the $KUBEPW password variable is not exported
set +o allexport  # Make sure variables are not automatically exported
read -rs -p "- Enter kubeadmin token (this will not be echoed to the console and the variable will not be exported): " KUBEPW < /dev/tty &&
echo

# Log in as kubeadmin:
oc login --token="${KUBEPW[0]}" --server="${APIURL[0]}"
RESULT=$?
if [[ "${RESULT}" != "0" ]]; then
  echo "Login unsuccessful. Exiting."
  exit 0
else
  OCPUSER=$(oc whoami)
  echo "Now logged in as ${OCPUSER}."
fi
echo
}

function enable_uwm ()
{
echo "########### Enabling user workload monitoring ##########"
# Create the `cluster-monitoring-config` ConfigMap if it does not already exist:
CONFMAPNAME=$(oc get configmap cluster-monitoring-config -n openshift-monitoring 2>/dev/null | grep -s 'cluster-monitoring-config' | awk '{print $1}')
if [[ "${CONFMAPNAME}" = "cluster-monitoring-config" ]]; then
  echo "configmap/cluster-monitoring-config already exists in the openshift-monitoring namespace."
else
  oc create configmap cluster-monitoring-config -n openshift-monitoring
fi

# Create a `${TMP}/cluster-monitoring-config.yaml` file and append a `data/config.yaml` section that will enable user workload monitoring when applied:
oc get configmap cluster-monitoring-config -n openshift-monitoring -o yaml > "${TMP}/cluster-monitoring-config.yaml"
cat <<EOF >> "${TMP}/cluster-monitoring-config.yaml"
data:
  config.yaml: |
    enableUserWorkload: true
EOF

# Apply the `${TMP}/cluster-monitoring-config.yaml` configuration to the cluster:
oc apply -f "${TMP}/cluster-monitoring-config.yaml"

# Wait for user workload monitoring Pods to start in the `openshift-user-workload-monitoring` namespace:
echo -n "Waiting for OpenShift user workload monitoring Pods."
while [[ "$(oc get pods -n openshift-user-workload-monitoring --field-selector=status.phase!=Running 2>/dev/null | wc -l)" -gt 1 ]] || \
      [[ "$(oc get pods -n openshift-user-workload-monitoring 2>/dev/null | grep -sc 'prometheus-operator')" -lt 1 ]] || \
      [[ "$(oc get pods -n openshift-user-workload-monitoring 2>/dev/null | grep -sc 'prometheus-user-workload')" -lt 1 ]] || \
      [[ "$(oc get pods -n openshift-user-workload-monitoring 2>/dev/null | grep -sc 'thanos-ruler-user-workload')" -lt 1 ]]; do
  echo -n "."
  sleep 5
done
echo

# List newly created pods in the `openshift-user-workload-monitoring` namespace:
oc get pods -n openshift-user-workload-monitoring
echo
}

function deploy_user_app ()
{
echo "############ Deploying a user application  #############"
# Deploy an application named `prometheus-example-app` in a project called `ns1`, using an existing `./uwm_setup_files/prometheus-example-app.yaml` file:
oc apply -f ./uwm_setup_files/prometheus-example-app.yaml

# Review the application's status:
sleep 10
oc get pods -n ns1
oc get deployment.apps -n ns1
oc get svc -n ns1
echo
}

function create_users ()
{
echo "### Configuring HTPasswd IP, create secret and users ###"
# Create an HTPasswd file called `${TMP}/htpasswd_file` if it does not already exist and add new users. If the file does already exist, then add/update users. These users will later be assigned different monitoring roles:
if [[ -f "${TMP}/htpasswd_file" ]]; then
  htpasswd -b "${TMP}/htpasswd_file" user1 Passwd01
else
  htpasswd -c -B -b "${TMP}/htpasswd_file" user1 Passwd01
fi
htpasswd -b "${TMP}/htpasswd_file" user2 Passwd01
htpasswd -b "${TMP}/htpasswd_file" user3 Passwd01

# Create a secret resource called `localusers` from the `${TMP}/htpasswd_file` file. If a `localusers` secret already exists, ask for user confirmation before deleting and recreating:
SECRETNAME=$(oc get secrets -n openshift-config | grep -is 'localusers' | awk '{print $1}')
if [[ "${SECRETNAME}" = "localusers" ]]; then
  while true; do
    read -rp "secret/localusers already exists in the openshift-config namespace. Delete it and create a new secret to include the users defined above? (y/n): " YESNO
    case $YESNO in
        y )
          oc delete secret/localusers -n openshift-config
          oc create secret generic localusers --from-file htpasswd="${TMP}/htpasswd_file" -n openshift-config
          break
          ;;
        n )
          echo "Users required by this script might not exist in current secret/localusers resource. Exiting."
          exit 0
          ;;
        * )
          echo "Please answer 'y' or 'n':"
          ;;
    esac
  done
else
  oc create secret generic localusers --from-file htpasswd="${TMP}/htpasswd_file" -n openshift-config
fi

# Update the `cluster` oauth configuration to enable an `htpasswd` identity provider which references the `localusers` secret. Once the updated configuration is saved, the HTPasswd users will be able to authenticate into the cluster:
oc get oauths.config.openshift.io cluster -n openshift-authentication -o yaml | grep -v '^spec:' > "${TMP}/oauth.yaml"
cat <<EOF >> "${TMP}/oauth.yaml"
spec:
  identityProviders:
  - htpasswd:
      fileData:
        name: localusers
    mappingMethod: claim
    name: myusers
    type: HTPasswd
EOF

# Apply the `${TMP}/oauth.yaml` configuration to the cluster:
oc apply -f "${TMP}/oauth.yaml"

# Wait some time while the oauth-openshift-* Pods restart, applying the new configuration:
echo "Waiting for oauth Pods to restart..."
sleep 60
oc get pods -n openshift-authentication
echo "Login information will be provided at the end of this script."
echo
}

function apply_roles ()
{
echo "################### Applying roles #####################"
# Provide a message about upcoming "Warning: User '<user>' not found" warnings:
echo "You can ignore 'Warning: User '<user>' not found' warning messages which may appear shortly..."

# Assign different monitoring roles `user1`, `user2` and `user3`:
# `monitoring-rules-view` allows reading PrometheusRule custom resources within the namespace:
oc policy add-role-to-user monitoring-rules-view user1 -n ns1
# `monitoring-rules-edit` allows creating, modifying, and deleting PrometheusRule custom resources matching the permitted namespace:
oc policy add-role-to-user monitoring-rules-edit user2 -n ns1
# `monitoring-edit` gives the same permissions as `monitoring-rules-edit`. Additionally, it allows creating new scraping targets for services or Pods. It also allows creating, modifying, and deleting ServiceMonitors and PodMonitors:
oc policy add-role-to-user monitoring-edit user3 -n ns1
echo
}

function add_service_monitor ()
{
echo "############### Adding a service monitor ###############"
# Log in as `user3`. `user3` has been assigned the `monitoring-edit` role:
oc login -u user3 -p Passwd01 --server="${APIURL[0]}"
RESULT=$?
while [[ ${RESULT} != "0" ]]; do
  echo "Waiting for oauth Pods to restart. Trying again in 10 seconds..."
  sleep 10
  oc login -u user3 -p Passwd01 --server="${APIURL[0]}"
  RESULT=$?
done

# Add a service monitor to enable OpenShift Monitoring to scrape metrics exposed by the `prometheus-example-app` user app. Add a ServiceMonitor resource called `prometheus-example-monitor` by applying the existing configuration file `./uwm_setup_files/example-app-service-monitor.yaml`:
oc apply -f ./uwm_setup_files/example-app-service-monitor.yaml

# Wait for the `prometheus-example-monitor` ServiceMonitor to start:
echo -n "Checking the service monitor's status."
sleep 5
while [[ $(oc get servicemonitor -n ns1 2>/dev/null | grep -cs 'prometheus-example-monitor') -lt 1 ]]; do
  echo -n "."
  sleep 5
done
oc get servicemonitor -n ns1
echo
}

function create_alerting_rule ()
{
echo "############## Creating an alerting rule ###############"
# Log in as `user2`. `user2` has been assigned the `monitoring-rules-edit` role:
oc login -u user2 -p Passwd01 --server="${APIURL[0]}"
echo "Now logged in as $(oc whoami) with monitoring-rules-edit role."

# Create an alerting rule named `example-alert` that fires an alert when the version metric exposed by the sample service becomes `0`. To do this, apply existing configuration file `./uwm_setup_files/example-app-alerting-rule.yaml`:
oc apply -f ./uwm_setup_files/example-app-alerting-rule.yaml

# Wait for the `prometheus-example-rule` alerting rule to be created:
echo -n "Checking the alerting rule's status."
sleep 5
while [[ $(oc get prometheusrule.monitoring.coreos.com/prometheus-example-rule -n ns1 2>/dev/null | grep -cs 'prometheus-example-rule') -lt 1 ]]; do
  echo -n "."
  sleep 5
done
oc get prometheusrule.monitoring.coreos.com/prometheus-example-rule -n ns1
echo
}

function provide_login_details ()
{
echo "########## Outputting login information ##########"

# Provide details on how to login and how to change user passwords:
echo "Test users 'user1', 'user2' and 'user3' have been allocated the password 'Passwd01'."
echo "To change user passwords, update the htpasswd file:"; echo
# shellcheck disable=SC2086
echo "htpasswd -b "${TMP}/htpasswd_file" <user_name> <password>"; echo
echo "Then, update the secret. You need 'cluster-admin' privileges to run the following command:"; echo
# shellcheck disable=SC2086
echo "oc create secret generic localusers --from-file htpasswd="${TMP}/htpasswd_file" --dry-run -o yaml | oc replace -n openshift-config -f -"; echo
echo "After running that command, oauth Pods are restarted. You will need to wait for the restart to complete before the updated credentials become active."; echo
}

function provide_urls ()
{
echo "########## Outputting cluster and Thanos URLS ##########"

# Provide OpenShift web console and the Thanos UI URLs to stdout. Log in as kubeadmin again first:
oc login --token="${KUBEPW[0]}" --server="${APIURL[0]}"
echo "Now logged in as ${OCPUSER}."
CONSOLEURL=$(oc get routes -n openshift-console | grep -is '^console' | awk '{print $2}')
THANOSURL=$(oc -n openshift-user-workload-monitoring get routes | grep -s 'thanos-ruler' | awk '{print $2}')
echo
echo "Access metrics in the OpenShift web console at https://${CONSOLEURL} -> Monitoring -> Metrics. Try querying the 'version' metric in the PromQL prompt to see version metrics for the 'prometheus-example-app' service."; echo
echo "Alternatively, access metrics in the Thanos web console at https://${THANOSURL}."
echo
}

# Main:
notice
kubeadmin_login
enable_uwm
deploy_user_app
create_users
apply_roles
add_service_monitor
create_alerting_rule
provide_login_details
provide_urls
