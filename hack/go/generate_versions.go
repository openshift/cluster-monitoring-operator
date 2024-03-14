package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/blang/semver/v4"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/olekukonko/tablewriter"
	"gopkg.in/yaml.v3"
)

const (
	mainBranch          = "master"
	metricsServerRepo   = "openshift/kubernetes-metrics-server"
	versionFile         = "../../jsonnet/versions.yaml"
	versionNotFound     = "N/A"
	OCPVersionHeader    = " OCP Version"
	depsVersionsFile    = "../../Documentation/deps-versions.md"
	versionFileComments = `---
# This file is meant to be managed by hack/go/generate_versions.go script
# Versions provided here are mapped to 'app.kubernetes.io/version' label in all generated manifests

`
)

type Components struct {
	Repos    map[string]string `yaml:"repos"`
	Versions map[string]string `yaml:"versions"`
}

func main() {
	// PULL_BASE_REF will be set by CI.
	pullBaseRef, set := os.LookupEnv("PULL_BASE_REF")
	if !set {
		pullBaseRef = mainBranch
	}

	if pullBaseRef != mainBranch {
		log.Printf(
			"Components versions are only updated on '%s' branch for now. Nothing to do against the branch '%s'.",
			mainBranch,
			pullBaseRef,
		)
		os.Exit(0)
	}

	data, err := os.ReadFile(versionFile)
	if err != nil {
		log.Fatalf("error reading file: %v", err)
	}
	components := Components{}
	err = yaml.Unmarshal(data, &components)
	if err != nil {
		log.Fatalf("error while unmarshalling: %v", err)
	}

	err = updateVersionFile(versionFile, components)
	if err != nil {
		log.Fatalf("error updating %s: %v", versionFile, err)
	}
	err = updateDepsVersionsFile(depsVersionsFile, components)
	if err != nil {
		log.Fatalf("error updating %s: %v", versionFile, err)
	}
}

func trimmedVersion(rawVersion string) string {
	return strings.TrimSuffix(strings.TrimPrefix(rawVersion, "v"), "\n")
}

func updateVersionFile(fileP string, components Components) error {
	keys := []string{}
	for component := range components.Repos {
		keys = append(keys, component)
	}
	sort.Strings(keys)

	for _, component := range keys {
		knownVersion, _ := components.Versions[component]
		newVersion, err := getVersion(components.Repos[component], mainBranch)
		if err != nil {
			log.Fatalf("couldn't fetch the new version for %s: %v", component, err)
		}
		newVersion = trimmedVersion(newVersion)
		if newVersion != knownVersion {
			log.Printf("%s version changed from '%s' to '%s'", component, knownVersion, newVersion)
			components.Versions[component] = newVersion
		}
	}

	data, err := yaml.Marshal(&components)
	if err != nil {
		return fmt.Errorf("error while marshalling: %v", err)
	}
	data = []byte(versionFileComments + string(data))
	err = os.WriteFile(fileP, data, 0o644)
	if err != nil {
		return fmt.Errorf("error writing file: %v", err)
	}
	return nil
}

func updateDepsVersionsFile(fileP string, components Components) error {
	file, err := os.OpenFile(fileP, os.O_RDWR|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("error opening file: %v", err)
	}
	table := tablewriter.NewWriter(file)
	header := []string{OCPVersionHeader}
	for component := range components.Repos {
		header = append(header, component)
	}
	sort.Strings(header)
	table.SetHeader(header)
	table.SetAutoFormatHeaders(false)
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	table.SetCenterSeparator("|")

	releaseVersion, err := semver.Make("4.10.0")
	if err != nil {
		return fmt.Errorf("error parsing the OCP version: %v", err)
	}
	var rows [][]string
	for {
		// We'll only/always consider components known in mainBranch.
		versions := getVersions(releaseBranch(releaseVersion), components)
		if len(versions) == 0 {
			// TODO: increment major when needed.
			break
		}
		versions[OCPVersionHeader] = releaseBranch(releaseVersion)
		row := []string{}
		for _, h := range header {
			version := versionNotFound
			if v, found := versions[h]; found {
				version = v
			}
			row = append(row, version)
		}
		rows = append(rows, row)
		err = releaseVersion.IncrementMinor()
		if err != nil {
			return err
		}
	}
	// Latest version at the beginning.
	slices.Reverse(rows)
	table.AppendBulk(rows)
	table.Render()
	return nil
}

func versionWithLink(version, repo, ref string) string {
	return fmt.Sprintf("[%s](%s)", version, fmt.Sprintf("https://github.com/%s/blob/%s", repo, ref))
}

func releaseBranch(version semver.Version) string {
	return fmt.Sprintf("release-%d.%d", version.Major, version.Minor)
}

func getVersions(ref string, components Components) map[string]string {
	versions := map[string]string{}
	for component, repo := range components.Repos {
		rawVersion, err := getVersion(repo, ref)
		if err != nil {
			continue
		}
		versions[component] = versionWithLink(trimmedVersion(rawVersion), repo, ref)
	}
	return versions
}

func getVersion(repo, ref string) (string, error) {
	baseURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s", repo, ref)
	links := []string{fmt.Sprintf("%s/VERSION", baseURL)}
	if repo == metricsServerRepo {
		links = []string{
			// metrics-server < 0.7.0
			fmt.Sprintf("%s/manifests/release/kustomization.yaml", baseURL),
			// metrics-server >= 0.7.0
			fmt.Sprintf("%s/manifests/components/release/kustomization.yaml", baseURL),
		}
	}

	var raw string
	var err error
	for _, link := range links {
		raw, err = fetchVersion(link)
		if err == nil {
			break
		}
	}
	if err != nil {
		return "", err
	}

	if repo == metricsServerRepo {
		var data map[string]interface{}
		err := yaml.Unmarshal([]byte(raw), &data)
		if err != nil {
			return "", err
		}
		// keep it simple: panic if it's no more the case.
		raw = data["images"].([]interface{})[0].(map[string]interface{})["newTag"].(string)
	}
	return raw, nil
}

func fetchVersion(path string) (string, error) {
	resp, err := retryablehttp.Get(path)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("non 200 response")
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
