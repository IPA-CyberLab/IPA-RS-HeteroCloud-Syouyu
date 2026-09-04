# Third-party notices

## Garage

Syouyu deploys [Garage](https://garagehq.deuxfleurs.fr/) v2.3.0 as its S3 data
plane by referencing the upstream `dxflrs/garage:v2.3.0` container image.
Garage is distributed by its authors under the GNU Affero General Public
License v3.0. Syouyu does not incorporate Garage into the Syouyu binary, and
the upstream image and source retain their original license.

The GarageNode Kubernetes CustomResourceDefinition under
`deploy/helm/heterocloud-syouyu/crds` is adapted from the Garage v2.3.0
Kubernetes deployment files and remains subject to Garage's AGPL-3.0 license.
The upstream source and license are available at:

- https://github.com/deuxfleurs-org/garage/tree/v2.3.0/script/k8s/crd
- https://github.com/deuxfleurs-org/garage/blob/v2.3.0/LICENSE

All other Syouyu-authored source code and deployment material is licensed
under the repository's MIT License unless a file states otherwise.
