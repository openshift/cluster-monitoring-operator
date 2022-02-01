package alert

import (
	"context"
	"sort"
	"sync"

	yaml2 "gopkg.in/yaml.v2"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/klog/v2"

	"github.com/prometheus/prometheus/model/relabel"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
)

// DefaultRelabelGroup is the name of the group containing the default relabel
// rules read from the assets.  Groups are combined in lexicographical order
// before being written to the secret.
const DefaultRelabelGroup = "000-default"

// relabelSecretKey is the key in the secret containing the additional configs.
const relabelSecretKey = "config.yaml"

// Relabeler manages the additional alert relabel configs by allowing components
// to manage groups of rules, which are then combined into a single config.
type Relabeler struct {
	client *client.Client
	assets *manifests.Assets
	secret *corev1.Secret
	groups map[string][]relabel.Config

	sync.RWMutex
}

// NewRelabeler returns a new Relabeler instance, or an error if the default
// relabel configs cannot be read from the assets.
func NewRelabler(client *client.Client, assets *manifests.Assets) (*Relabeler, error) {
	r := &Relabeler{
		client: client,
		assets: assets,
		groups: make(map[string][]relabel.Config, 1),
	}

	secret, configs, err := r.defaultConfigs()
	if err != nil {
		return nil, err
	}

	r.secret = secret
	r.groups[DefaultRelabelGroup] = configs

	return r, nil
}

// DeleteGroup removes the named group from the set of relabel configs.  Clients
// are responsible for calling WriteSecret to actually write the configs out to
// the Kubernetes secret.
func (r *Relabeler) DeleteGroup(group string) {
	klog.V(4).Infof("Alert relabeler removing group: %q", group)

	r.Lock()
	defer r.Unlock()

	delete(r.groups, group)
}

// UpdateGroup sets the contents of the named group to the given set of configs.
// Clients are responsible for calling WriteSecret to actually write the configs
// out to the Kubernetes secret.
func (r *Relabeler) UpdateGroup(group string, configs []relabel.Config) {
	klog.V(4).Infof("Alert relabeler updating group: %q", group)

	r.Lock()
	defer r.Unlock()

	r.groups[group] = configs
}

// WriteSecret combines the rules from each group, in lexicographical order by
// group name, and writes them to the Kubernetes secret.
func (r *Relabeler) WriteSecret() (*corev1.Secret, error) {
	klog.V(4).Info("Alert relabeler writing secret")

	configs := r.combinedConfigs()

	yamlData, err := yaml2.Marshal(configs)
	if err != nil {
		return nil, err
	}

	secret := r.secret.DeepCopy()
	secret.StringData = map[string]string{
		relabelSecretKey: string(yamlData),
	}

	if err := r.client.CreateOrUpdateSecret(context.TODO(), secret); err != nil {
		return nil, err
	}

	return secret, nil
}

// combinedConfigs returns a single list of relabel configs by iterating over
// the group names in lexicographical order and appending all configs.
func (r *Relabeler) combinedConfigs() []relabel.Config {
	r.RLock()
	defer r.RUnlock()

	var configs []relabel.Config

	for _, group := range sortedMapKeys(r.groups) {
		configs = append(configs, r.groups[group]...)
	}

	return configs
}

// defaultConfigs loads the default secret containing alert relabel configs from
// the assets, and returns the secret and decoded configs, or an error.
func (r *Relabeler) defaultConfigs() (*corev1.Secret, []relabel.Config, error) {
	// TODO(bison): This panics if it can't read the asset, but I guess that's
	// fine given that the assets are included as bindata at build time.
	s := r.assets.MustNewAssetReader(manifests.PrometheusK8sAlertRelabelConfigs)

	secret := &corev1.Secret{}
	if err := yaml.NewYAMLOrJSONDecoder(s, 100).Decode(secret); err != nil {
		return nil, nil, err
	}

	configs := []relabel.Config{}
	yamlData := []byte(secret.StringData[relabelSecretKey])
	if err := yaml2.UnmarshalStrict(yamlData, &configs); err != nil {
		return nil, nil, err
	}

	return secret, configs, nil
}

// sortedMapKeys returns a sorted a list of map keys.
func sortedMapKeys(m map[string][]relabel.Config) []string {
	keys := make([]string, len(m))

	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)
	return keys
}
