# How to Contribute

cluster-monitoring-operator projects are [Apache 2.0 licensed](LICENSE) and accept contributions via GitHub pull requests.
This document outlines some of the conventions on development workflow, commit message formatting, contact points and other resources to make it easier to get your contribution accepted.

# Certificate of Origin

By contributing to this project you agree to the Developer Certificate of Origin (DCO). 
This document was created by the Linux Kernel community and is a simple statement that you, as a contributor, have the legal right to make the contribution. See the [DCO](DCO) file for details.

# Notes
Cluster Monitoring Operator is part of OpenShift and therefore follows the [OpenShift Life Cycle](https://access.redhat.com/support/policy/updates/openshift)

You should keep this in mind when decding in which release you want your feature or fix.

# Contribution Flow
Before you get started, you have to perform the following **mandatory** steps:
* Open an bug in Bugzilla
* Fork this repository

If you want to make changes to the actual code, please follow the [Coding Style](#coding-style) for code changes.

## General workflow information
These steps outline the general contribution workflow:

* Create a topic branch from where you want to base your work (usually master).
* Make commits of logical units.
* Make sure your commit messages are in the proper format (see [Format of the Commit Message](#format-of-the-commit-message))
* Push your changes to a topic branch in your fork of the repository.
* Make sure the tests pass, and add any new tests as appropriate.
* Submit a pull request to the original repository. (see [Format of Pull Requests](#format-of-pull-requests))

## Required tools
To allow scripts and `make` targets working correctly, ensure you have following tools installed in your system:

* golang (see `go.mod` file for minimum required go version)
* `awk` (GNU variant)
* `sed` (GNU variant)
* `make`
* `curl`
* python2 and pyyaml package

All other tools are downloaded automatically by `make` and put into `tmp/bin` directory.

## Working with jsonnet
This project is making use of a lot of upstream projects and imports them.

All tools required, should be installed on demand as part of the `make` command starting from release-4.6.

Prior to release-4.6 to work with jsonnet you should have [jsonnet bundler](https://github.com/jsonnet-bundler/jsonnet-bundler) installed and [updated](https://github.com/coreos/kube-prometheus#update-jb).

Assuming you have made your changes upstream ([see an example change](https://github.com/kubernetes-monitoring/kubernetes-mixin/pull/466/files)),
you can now go ahead and update the dependency.

Since release-4.6:

```
make jsonnet/vendor --always-make
```

Earlier release branches:
```
cd jsonnet
jb update
```

Now make sure that you only update or adjust the dependency you need to and commit that update

```
git add -p jsonnet/jsonnetfile.lock.json
git commit -m 'jsonnet: <meaningful message about what you did>'
git push
git checkout jsonnet/jsonnet.lock.json
```
See [Format of the Commit Message](#format-of-the-commit-message) for help on how to format your commit message


The last step is to regenerate all assets.

Since release-4.6, this just requires the following command:

```
make generate
```

For all older branches this is easiest done in a container using the following command

```
make generate-in-docker
```
or if you are on a Mac

```
MAKE=make make generate-in-docker
```

At this point, you should follow a standard git workflow:

* review your changes using `git diff`
* add all generated files in one commit
* push to your branch
* open a Pull Request (see [Format of Pull Requests](#format-of-pull-requests))

## Troubleshooting

- In case generation step or CI `ci/prow/generate` check fails, try running `make clean` to remove stale jsonnet vendor directory.

- In case you have problems with `make generate` due to problems with system-wide tooling, you can use slower
`make generate-in-docker` target which will install necessary tools in containerized environment and will generate assets.
This targets needs `docker` to be installed on host and was not tested with other container runtime environments.

## Coding Style

cluster-monitoring-operator projects written in Go follow a set of style guidelines that we've documented [here](https://github.com/coreos/docs/tree/master/golang).
Please follow them when working on your contributions.

## Format of Pull Requests
We are making heavy use of bots and integrations.
In order for those to work properly, your Pull Request should match the following structure:

```
Bug 123456: this is the exact problem or fix
```

## Format of the Commit Message

We follow a rough convention for commit messages that is designed to answer two
questions: what changed and why. The subject line should feature the what and
the body of the commit should describe the why.

```
scripts: add the test-cluster command

this uses tmux to setup a test cluster that you can easily kill and
start for debugging.

Fixes #38
```

The format can be described more formally as follows:

```
<subsystem>: <what changed>
<BLANK LINE>
<why this change was made>
<BLANK LINE>
<footer>
```

The first line is the subject and should be no longer than 70 characters, the
second line is always blank, and other lines should be wrapped at 80 characters.
This allows the message to be easier to read on GitHub as well as in various
git tools.



Thank you for contributing!
