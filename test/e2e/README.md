# Running e2e tests

```bash
# build ${IMAGE} containing the e2e test binary
make crossbuild-e2e build-docker-test

# push the test image
docker push "${IMAGE}"

# create a job that launches the e2e test
oc process -f "test/e2e/e2e-job-template.yaml" -p IMAGE="${IMAGE}" | oc apply -n openshift-monitoring -f -
```
