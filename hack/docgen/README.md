# Cluster Monitoring Operator Docgen

This package contains the code that automatically generates `Documentation/api.md` the code is heavily inspired by the (current) prometheus-operator codegen solution however, some adaptations were made to the format to alight it as much as possible with the OpenShift docs format.

### Goal
The goal of this code is to automate the generation of documentation that will not only be used by users but also by our technical writers who have to maintain an updated version of it on OpenShift docs. Because of this requirement, a custom code solution was used instead of an open source one to facilitate compliance with the OpenShift docs format. 

### How it works
The code will generate the documentation based on comments in the golang code. It will ingest the file `pkg/manifests/types.go` which contains all the types used by CMO and parse it accordingly.

#### External links

External links are also dynamically generated to match the current version of Kubernetes and Prometheus Operator by passing to the program as parameters the version of both.

#### Required fields

Some data types require that some fields are present when specified while others can be omitted. If a field can be omitted it should have the tag `omitempty` in its JSON, this will make it so it's omitted from the `Required` section.

#### Ignoring fields from the doc

Some fields can be omitted from the documentation if their documentation starts with `// OmitFromDoc`.

### How to run

To run update the documentation run:

```bash
make docs --always-make
```