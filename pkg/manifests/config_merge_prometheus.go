// Copyright 2018 The Cluster Monitoring Operator Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package manifests

import (
	"fmt"
	"strconv"
	"strings"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
)

const serviceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// clusterMonitoringPrometheusSpecEmpty reports whether the CR's prometheusConfig stanza
// contains no user-set field.
func clusterMonitoringPrometheusSpecEmpty(pc configv1alpha1.PrometheusConfig) bool {
	if len(pc.AdditionalAlertmanagerConfigs) > 0 {
		return false
	}
	if pc.EnforcedBodySizeLimitBytes != 0 {
		return false
	}
	if len(pc.ExternalLabels) > 0 {
		return false
	}
	if pc.LogLevel != "" {
		return false
	}
	if len(pc.NodeSelector) > 0 {
		return false
	}
	if pc.QueryLogFile != "" {
		return false
	}
	if len(pc.RemoteWrite) > 0 {
		return false
	}
	if len(pc.Resources) > 0 {
		return false
	}
	if !retentionCRDEmpty(pc.Retention) {
		return false
	}
	if len(pc.Tolerations) > 0 {
		return false
	}
	if len(pc.TopologySpreadConstraints) > 0 {
		return false
	}
	if pc.CollectionProfile != "" {
		return false
	}
	if pc.VolumeClaimTemplate != nil {
		return false
	}
	return true
}

func retentionCRDEmpty(r configv1alpha1.Retention) bool {
	return r.Duration == "" && r.Size == ""
}

func collectionProfileCRDToManifest(cp configv1alpha1.CollectionProfile) CollectionProfile {
	switch cp {
	case configv1alpha1.CollectionProfileFull:
		return FullCollectionProfile
	case configv1alpha1.CollectionProfileMinimal:
		return MinimalCollectionProfile
	default:
		return ""
	}
}

func externalLabelsFromCRD(labels []configv1alpha1.Label) ExternalLabels {
	if len(labels) == 0 {
		return nil
	}
	out := make(ExternalLabels, len(labels))
	for _, l := range labels {
		out[l.Key] = l.Value
	}
	return out
}

func secretKeySelectorFromCRD(s configv1alpha1.SecretKeySelector) *v1.SecretKeySelector {
	if s.Name == "" {
		return nil
	}
	return &v1.SecretKeySelector{
		LocalObjectReference: v1.LocalObjectReference{Name: s.Name},
		Key:                  s.Key,
	}
}

func alertmanagerSchemeFromCRD(scheme configv1alpha1.AlertmanagerScheme) string {
	switch scheme {
	case configv1alpha1.AlertmanagerSchemeHTTPS:
		return "https"
	case configv1alpha1.AlertmanagerSchemeHTTP:
		return "http"
	default:
		return ""
	}
}

func tlsConfigFromCRD(tc configv1alpha1.TLSConfig) TLSConfig {
	out := TLSConfig{
		ServerName: tc.ServerName,
	}
	if sel := secretKeySelectorFromCRD(tc.CA); sel != nil {
		out.CA = sel
	}
	if sel := secretKeySelectorFromCRD(tc.Cert); sel != nil {
		out.Cert = sel
	}
	if sel := secretKeySelectorFromCRD(tc.Key); sel != nil {
		out.Key = sel
	}
	if tc.CertificateVerification == configv1alpha1.CertificateVerificationSkipVerify {
		out.InsecureSkipVerify = true
	}
	return out
}

func safeTLSConfigFromCRD(tc configv1alpha1.TLSConfig) *monv1.SafeTLSConfig {
	if tc.CA.Name == "" && tc.Cert.Name == "" && tc.Key.Name == "" && tc.ServerName == "" && tc.CertificateVerification == "" {
		return nil
	}
	out := &monv1.SafeTLSConfig{}
	if sel := secretKeySelectorFromCRD(tc.CA); sel != nil {
		out.CA = monv1.SecretOrConfigMap{Secret: sel}
	}
	if sel := secretKeySelectorFromCRD(tc.Cert); sel != nil {
		out.Cert = monv1.SecretOrConfigMap{Secret: sel}
	}
	if sel := secretKeySelectorFromCRD(tc.Key); sel != nil {
		out.KeySecret = sel
	}
	if tc.ServerName != "" {
		out.ServerName = ptr.To(tc.ServerName)
	}
	if tc.CertificateVerification == configv1alpha1.CertificateVerificationSkipVerify {
		out.InsecureSkipVerify = ptr.To(true)
	}
	return out
}

func additionalAlertmanagerConfigsFromCRD(configs []configv1alpha1.AdditionalAlertmanagerConfig) []AdditionalAlertmanagerConfig {
	if len(configs) == 0 {
		return nil
	}
	out := make([]AdditionalAlertmanagerConfig, 0, len(configs))
	for _, ac := range configs {
		cfg := AdditionalAlertmanagerConfig{
			APIVersion:    "v2",
			PathPrefix:    ac.PathPrefix,
			StaticConfigs: ac.StaticConfigs,
		}
		if scheme := alertmanagerSchemeFromCRD(ac.Scheme); scheme != "" {
			cfg.Scheme = scheme
		}
		if ac.Authorization.Type == configv1alpha1.AuthorizationTypeBearerToken {
			cfg.BearerToken = secretKeySelectorFromCRD(ac.Authorization.BearerToken)
		}
		if ac.TimeoutSeconds > 0 {
			timeout := fmt.Sprintf("%ds", ac.TimeoutSeconds)
			cfg.Timeout = &timeout
		}
		if ac.TLSConfig.CA.Name != "" || ac.TLSConfig.Cert.Name != "" || ac.TLSConfig.Key.Name != "" ||
			ac.TLSConfig.ServerName != "" || ac.TLSConfig.CertificateVerification != "" {
			cfg.TLSConfig = tlsConfigFromCRD(ac.TLSConfig)
		}
		out = append(out, cfg)
	}
	return out
}

func remoteWriteHeadersFromCRD(headers []configv1alpha1.PrometheusRemoteWriteHeader) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	for _, h := range headers {
		if h.Value != nil {
			out[h.Name] = *h.Value
		} else {
			out[h.Name] = ""
		}
	}
	return out
}

func metadataConfigFromCRD(mc configv1alpha1.MetadataConfig) *monv1.MetadataConfig {
	if mc.SendPolicy == "" {
		return nil
	}
	switch mc.SendPolicy {
	case configv1alpha1.MetadataConfigSendPolicyDefault:
		return &monv1.MetadataConfig{Send: true}
	case configv1alpha1.MetadataConfigSendPolicyCustom:
		out := &monv1.MetadataConfig{Send: true}
		if mc.Custom.SendIntervalSeconds > 0 {
			out.SendInterval = monv1.Duration(fmt.Sprintf("%ds", mc.Custom.SendIntervalSeconds))
		}
		return out
	default:
		return nil
	}
}

func queueConfigFromCRD(qc configv1alpha1.QueueConfig) *monv1.QueueConfig {
	if qc.Capacity == 0 && qc.MaxShards == 0 && qc.MinShards == 0 && qc.MaxSamplesPerSend == 0 &&
		qc.BatchSendDeadlineSeconds == 0 && qc.MinBackoffMilliseconds == 0 && qc.MaxBackoffMilliseconds == 0 &&
		qc.RateLimitedAction == "" {
		return nil
	}
	out := &monv1.QueueConfig{}
	if qc.Capacity > 0 {
		out.Capacity = int(qc.Capacity)
	}
	if qc.MaxShards > 0 {
		out.MaxShards = int(qc.MaxShards)
	}
	if qc.MinShards > 0 {
		out.MinShards = int(qc.MinShards)
	}
	if qc.MaxSamplesPerSend > 0 {
		out.MaxSamplesPerSend = int(qc.MaxSamplesPerSend)
	}
	if qc.BatchSendDeadlineSeconds > 0 {
		out.BatchSendDeadline = ptr.To(monv1.Duration(fmt.Sprintf("%ds", qc.BatchSendDeadlineSeconds)))
	}
	if qc.MinBackoffMilliseconds > 0 {
		out.MinBackoff = ptr.To(monv1.Duration(fmt.Sprintf("%dms", qc.MinBackoffMilliseconds)))
	}
	if qc.MaxBackoffMilliseconds > 0 {
		out.MaxBackoff = ptr.To(monv1.Duration(fmt.Sprintf("%dms", qc.MaxBackoffMilliseconds)))
	}
	if qc.RateLimitedAction == configv1alpha1.RateLimitedActionRetry {
		out.RetryOnRateLimit = true
	}
	return out
}

func oauth2FromCRD(oauth2 configv1alpha1.OAuth2) *monv1.OAuth2 {
	if oauth2.TokenURL == "" {
		return nil
	}
	out := &monv1.OAuth2{
		TokenURL: oauth2.TokenURL,
		Scopes:   oauth2.Scopes,
	}
	if sel := secretKeySelectorFromCRD(oauth2.ClientID); sel != nil {
		out.ClientID = monv1.SecretOrConfigMap{Secret: sel}
	}
	if sel := secretKeySelectorFromCRD(oauth2.ClientSecret); sel != nil {
		out.ClientSecret = *sel
	}
	if len(oauth2.EndpointParams) > 0 {
		out.EndpointParams = make(map[string]string, len(oauth2.EndpointParams))
		for _, p := range oauth2.EndpointParams {
			if p.Value != nil {
				out.EndpointParams[p.Name] = *p.Value
			} else {
				out.EndpointParams[p.Name] = ""
			}
		}
	}
	return out
}

func sigv4FromCRD(sigv4 configv1alpha1.Sigv4) *monv1.Sigv4 {
	if sigv4.Region == "" && sigv4.AccessKey.Name == "" && sigv4.SecretKey.Name == "" &&
		sigv4.Profile == "" && sigv4.RoleArn == "" {
		return nil
	}
	out := &monv1.Sigv4{
		Region:  sigv4.Region,
		Profile: sigv4.Profile,
		RoleArn: sigv4.RoleArn,
	}
	out.AccessKey = secretKeySelectorFromCRD(sigv4.AccessKey)
	out.SecretKey = secretKeySelectorFromCRD(sigv4.SecretKey)
	return out
}

func relabelActionString(action configv1alpha1.RelabelAction) string {
	return strings.ToLower(string(action))
}

func relabelConfigFromCRD(rc configv1alpha1.RelabelConfig) monv1.RelabelConfig {
	out := monv1.RelabelConfig{
		Regex: rc.Regex,
	}
	if len(rc.SourceLabels) > 0 {
		out.SourceLabels = make([]monv1.LabelName, len(rc.SourceLabels))
		for i, l := range rc.SourceLabels {
			out.SourceLabels[i] = monv1.LabelName(l)
		}
	}
	if rc.Separator != "" {
		out.Separator = ptr.To(rc.Separator)
	}
	if rc.Action.Type != "" {
		out.Action = relabelActionString(rc.Action.Type)
	}
	switch rc.Action.Type {
	case configv1alpha1.RelabelActionReplace:
		out.TargetLabel = rc.Action.Replace.TargetLabel
		out.Replacement = rc.Action.Replace.Replacement
	case configv1alpha1.RelabelActionHashMod:
		out.TargetLabel = rc.Action.HashMod.TargetLabel
		if rc.Action.HashMod.Modulus > 0 {
			out.Modulus = uint64(rc.Action.HashMod.Modulus)
		}
	case configv1alpha1.RelabelActionLowercase:
		out.TargetLabel = rc.Action.Lowercase.TargetLabel
	case configv1alpha1.RelabelActionUppercase:
		out.TargetLabel = rc.Action.Uppercase.TargetLabel
	case configv1alpha1.RelabelActionKeepEqual:
		out.TargetLabel = rc.Action.KeepEqual.TargetLabel
	case configv1alpha1.RelabelActionDropEqual:
		out.TargetLabel = rc.Action.DropEqual.TargetLabel
	case configv1alpha1.RelabelActionLabelMap:
		out.Replacement = ptr.To(rc.Action.LabelMap.Replacement)
	}
	return out
}

func writeRelabelConfigsFromCRD(configs []configv1alpha1.RelabelConfig) []monv1.RelabelConfig {
	if len(configs) == 0 {
		return nil
	}
	out := make([]monv1.RelabelConfig, 0, len(configs))
	for _, rc := range configs {
		out = append(out, relabelConfigFromCRD(rc))
	}
	return out
}

func applyRemoteWriteAuthorizationFromCRD(auth configv1alpha1.RemoteWriteAuthorization, dst *RemoteWriteSpec) {
	switch auth.Type {
	case configv1alpha1.RemoteWriteAuthorizationTypeBearerToken:
		if sel := secretKeySelectorFromCRD(auth.BearerToken); sel != nil {
			dst.Authorization = &monv1.SafeAuthorization{
				Type:        "Bearer",
				Credentials: sel,
			}
		}
	case configv1alpha1.RemoteWriteAuthorizationTypeBasicAuth:
		username := secretKeySelectorFromCRD(auth.BasicAuth.Username)
		password := secretKeySelectorFromCRD(auth.BasicAuth.Password)
		if username != nil && password != nil {
			dst.BasicAuth = &monv1.BasicAuth{
				Username: *username,
				Password: *password,
			}
		}
	case configv1alpha1.RemoteWriteAuthorizationTypeOAuth2:
		dst.OAuth2 = oauth2FromCRD(auth.OAuth2)
	case configv1alpha1.RemoteWriteAuthorizationTypeSigV4:
		dst.Sigv4 = sigv4FromCRD(auth.Sigv4)
	case configv1alpha1.RemoteWriteAuthorizationTypeSafeAuthorization:
		if auth.SafeAuthorization != nil {
			dst.Authorization = &monv1.SafeAuthorization{
				Type:        "Bearer",
				Credentials: auth.SafeAuthorization,
			}
		}
	case configv1alpha1.RemoteWriteAuthorizationTypeServiceAccount:
		dst.BearerTokenFile = serviceAccountTokenPath
	}
}

func remoteWriteSpecsFromCRD(configs []configv1alpha1.RemoteWriteSpec) []RemoteWriteSpec {
	if len(configs) == 0 {
		return nil
	}
	out := make([]RemoteWriteSpec, 0, len(configs))
	for _, rw := range configs {
		cfg := RemoteWriteSpec{
			URL:      rw.URL,
			Name:     rw.Name,
			ProxyURL: rw.ProxyURL,
			Headers:  remoteWriteHeadersFromCRD(rw.Headers),
		}
		if rw.RemoteTimeoutSeconds > 0 {
			cfg.RemoteTimeout = fmt.Sprintf("%ds", rw.RemoteTimeoutSeconds)
		}
		if rw.ExemplarsMode == configv1alpha1.ExemplarsModeSend {
			cfg.SendExemplars = ptr.To(true)
		}
		if tls := safeTLSConfigFromCRD(rw.TLSConfig); tls != nil {
			cfg.TLSConfig = tls
		}
		if mc := metadataConfigFromCRD(rw.MetadataConfig); mc != nil {
			cfg.MetadataConfig = mc
		}
		if qc := queueConfigFromCRD(rw.QueueConfig); qc != nil {
			cfg.QueueConfig = qc
		}
		cfg.WriteRelabelConfigs = writeRelabelConfigsFromCRD(rw.WriteRelabelConfigs)
		if rw.AuthorizationConfig.Type != "" {
			applyRemoteWriteAuthorizationFromCRD(rw.AuthorizationConfig, &cfg)
		}
		out = append(out, cfg)
	}
	return out
}

func (c *Config) mergePrometheusK8sConfiguration(pc configv1alpha1.PrometheusConfig) {
	if c.ClusterMonitoringConfiguration.PrometheusK8sConfig != nil {
		return
	}
	if clusterMonitoringPrometheusSpecEmpty(pc) {
		return
	}

	cfg := &PrometheusK8sConfig{}

	if ll := logLevelCRDToManifest(pc.LogLevel); ll != "" {
		cfg.LogLevel = ll
	}
	cfg.NodeSelector = pc.NodeSelector
	cfg.Tolerations = pc.Tolerations
	cfg.TopologySpreadConstraints = pc.TopologySpreadConstraints
	cfg.Resources = containerResourcesFromCRD(pc.Resources)
	cfg.QueryLogFile = pc.QueryLogFile
	cfg.ExternalLabels = externalLabelsFromCRD(pc.ExternalLabels)
	cfg.AlertmanagerConfigs = additionalAlertmanagerConfigsFromCRD(pc.AdditionalAlertmanagerConfigs)
	cfg.RemoteWrite = remoteWriteSpecsFromCRD(pc.RemoteWrite)

	if pc.EnforcedBodySizeLimitBytes > 0 {
		cfg.EnforcedBodySizeLimit = strconv.FormatInt(pc.EnforcedBodySizeLimitBytes, 10)
	}
	if cp := collectionProfileCRDToManifest(pc.CollectionProfile); cp != "" {
		cfg.CollectionProfile = cp
	}
	if pc.Retention.Duration != "" {
		cfg.Retention = pc.Retention.Duration
	}
	if pc.Retention.Size != "" {
		cfg.RetentionSize = pc.Retention.Size
	}
	if pc.VolumeClaimTemplate != nil {
		cfg.VolumeClaimTemplate = persistentVolumeClaimToEmbedded(pc.VolumeClaimTemplate)
	}

	c.ClusterMonitoringConfiguration.PrometheusK8sConfig = cfg
}
