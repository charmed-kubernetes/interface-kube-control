# ops.interface_kube_control

## Rationale for this library
Many project need credentials in a kubernetes cluster to apply their workloads
using credentials from the kubernetes cluster.  Outside the cluster, these charms
need access to the cluster's API and credentials within that API. 

This library supports the `kube-control` relation to relate to a kubernetes
control-plane application, to provide access to that endpoint.

## Contributing
This library provides an interface for `ops` charms to use to connect to this interface. 

* Make adjustments
* test the changes by running tox

```sh
tox
```

* Raise your PR and contact maintainers
* Once merged, tag with an `ops-X.X.X` to publish a new pypi package

```sh
git switch main
git pull
git tag -a ops-X.X.X
git push <origin> tag ops-X.X.X
```
