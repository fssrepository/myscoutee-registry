# MyScoutee Registry Debian deployment

The Debian package is the primary controlled Linux/amd64 distribution for
Registry 1.0.0. It carries two separate Docker images: the non-root Go registry
and the first-party Nginx TLS edge. The installed Compose model is build-free,
pull-free, and uses a fixed project name so its persistent volume identity does
not depend on the invoking shell.

Install with APT so Docker Engine and Docker Compose v2 dependencies are
resolved:

```bash
sudo apt install ./myscoutee-registry_1.0.0_amd64.deb
```

Installation deliberately does not start or enable the registry and does not
load or pull images. Configure the deployment first:

```bash
sudoedit /etc/myscoutee-registry/registry.env
sudo install -o root -g root -m 0600 /secure/fullchain.pem \
  /etc/myscoutee-registry/tls/fullchain.pem
sudo install -o root -g root -m 0600 /secure/privkey.pem \
  /etc/myscoutee-registry/tls/privkey.pem
sudo myscoutee-registry-stack check
sudo systemctl enable --now myscoutee-registry
```

The check requires a non-placeholder scope and DNS hostname, matching usable
TLS material, explicit registry/VOPRF key-generation choices, the exact
package image references, and
`REGISTRY_OPERATOR_CONFIGURATION_CONFIRMED=true`. The first explicit start
verifies and loads both bundled images locally, then runs Compose with
`--pull never`.

Useful commands:

```bash
sudo myscoutee-registry-stack check
sudo myscoutee-registry-stack load-images
sudo myscoutee-registry-stack status
sudo myscoutee-registry-stack logs
sudo systemctl restart myscoutee-registry
```

The package has no self-update service, polling agent, or unattended download
path. An upgrade occurs only when an operator supplies a new package to
APT/dpkg. Package installation does not restart a running registry. Before an
upgrade, create and verify a consistent backup of the SQLite database,
registry signing key, and VOPRF keyring. After installation, run `check`,
review the package/version transition, and explicitly restart in the approved
maintenance window.

The environment file and TLS directory under `/etc/myscoutee-registry` are
created only on first install and preserved on upgrades. Registry state and
runtime private keys live in the Compose volume
`myscoutee-registry_registry-production-data`; neither package removal nor
purge deletes that volume. Purge also conservatively leaves operator-managed
configuration and TLS files in place. Delete them manually only after a
verified recovery-unit backup and an explicit decommissioning decision.

The portable tar.gz stack remains a secondary release-engineering and
restricted-environment carrier. It contains the same two images and Compose
contract, but the Debian package provides the managed host filesystem and
systemd integration.
