# Cluster Monitoring Operator Docgen

This package contains the code that automatically generates the following files:

* `Documentation/api.md`
* `Documentation/resources.md`
* `Documentation/api.adoc`
* `Documentation/resources.adoc`

The code is heavily inspired by the prometheus-operator's codegen tool however, some adaptations were made to the format to align it as much as possible with the OpenShift docs format.

## Goal

The goal of this code is to automate the generation of documentation that will not only be used by users but also by our technical writers who have to maintain an updated version of it for the OpenShift docs. Because of this requirement, a custom code solution was used instead of an open source one to facilitate compliance with the OpenShift docs format.

## How it works

### `Documentation/api.{adoc,md}`

For `Documentation/api.{adoc,md}`, the tool generates the documentation based on comments found in the `pkg/manifests/types.go` file.

#### External links

External links are also dynamically generated to match the current version of Kubernetes and Prometheus Operator by passing to the program as parameters the version of both.

#### Required fields

Some data types require that some fields are present when specified while others can be omitted. If a field can be omitted it should have the tag `omitempty` in its JSON, this will make it, so it's omitted from the `Required` section.

#### Ignoring fields from the doc

Some fields can be omitted from the documentation if their documentation starts with `// OmitFromDoc`.

### `Documentation/resources.{adoc,md}`

The tool parses the manifests from the `assets` and `manifests` directories, then it generates the page based on the `openshift.io/description` annotations.

## How to run

To update the documentation, run:

```bash
make docs --always-make
```
