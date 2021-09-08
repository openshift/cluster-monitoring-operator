# CMO Development


## Run CMO Locally
### Assumptions
* Should have a cluster running
* Has setup Go development env

### Build and Run CMO

The `make` target `run-local` builds the `operator` and runs CMO locally

```shell
export KUBECONFIG=/path/to/kubeconfig/file
make run-local
```

### Modify jsonnet

**TL;DR:**
1. build operator
1. use `hack/local-cmo.sh` to run the operator
1. modify assets/yamls
1. backport the changes to jsonnet


Sometimes we may not want to rebuild the operator. E.g. you may need
to figure out how the stack behaves after applying a change to generated
kubernetes manifest.  In other words, to modify the YAML in `assets/`
directory directly without needing to change the `jsonnet/` or
the `vendored` jsonnet files.

In these cases it is easier to change those yaml files manually, run
the operator (with those changed files) and later tweak `jsonnet`, than
to figuring out which parts of jsonnet code you may need to change to
fix an issue.

It is easier to follow the following workflow
#### Setup
1. Start openshift cluster ( e.g. using `cluster-bot` )
1. `export KUBECONFIG=/path/to/kubeconfig`
1. Build operator - `make operator`

#### Amend Assets
1. Amend yaml files in `assets/` directory
1. Run `hack/local-cmo.sh` (**does not** build the operator)
1. ☝☝☝ _rinse and repeat_

#### Finally:
1. Port the changes back to `jsonnet` or vendored `jsonnet`



## Updating individual vendored jsonnet code

NOTE: `jb update <repo-url>/<jsonnet-subdir>` doesn't seem to work since it
does not update the dependencies (at the time of writing)

Steps to update a bundle e.g. `kube-prometheus`:

```shell
cd jsonnet

```

Edit ``jsonnetfile.json ``and remove everything except the bundle you want to update
E.g. remove everything but *kube-prometheus* from the jsonnetfile.json file

```
jb update

```

`git add -p ` only the changes to the `version` and `sum`. E.g. the diff would
show as follows, add only those ignore the bundles that got deleted

```diff
diff --git a/jsonnet/jsonnetfile.lock.json b/jsonnet/jsonnetfile.lock.json
index 6d5adc26..eead7874 100644
--- a/jsonnet/jsonnetfile.lock.json
+++ b/jsonnet/jsonnetfile.lock.json
@@ -28,8 +28,8 @@
           "subdir": "grafonnet"
         }
       },
-      "version": "3082bfca110166cd69533fa3c0875fdb1b68c329",
-      "sum": "4/sUV0Kk+o8I+wlYxL9R6EPhL/NiLfYHk+NXlU64RUk="
+      "version": "05fb200ee1a1816fc1b4c522071d5606d8dd71c1",
+      "sum": "mEoObbqbyVaXrHFEJSM2Nad31tOvadzIevWuyNHHBgI="
     },
```

Revert back the changes to jsonnetfile.json and jsonnetfile.lock.json
```
git restore --  jsonnetfile.json jsonnnet.lock.json

```

Now you should have a `jsonnetfile.lock.json` that has only the updates to
the bundle `kube-prometheus`. Remove the  `vendor` and reinstall all bundles.

```
# reinstall all jsonnet based on the new lockfile
rm -rf vendor ; jb install

# Now you should have only the changes that is part of latest kube-prometheus
cd ..
make generate
git add everything and commit

```
