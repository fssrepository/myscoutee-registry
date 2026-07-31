# MyScoutee Registry packaging

This directory is the production release boundary for a standalone Registry
VM. Development containers and source mounts are intentionally outside it.

The release contains exactly two version-derived production images:

- `myscoutee-registry:<version>-prod`
- `myscoutee-registry-nginx:<version>-prod`

Build the images and Debian package from the repository root:

```bash
bash packaging/scripts/build-production.sh
bash packaging/scripts/package-production.sh
```

The command writes two release artifacts:

- `packaging/dist/myscoutee-registry_<version>_amd64.deb`
- `packaging/dist/myscoutee-registry-client-tools_<version>.tar.gz`

The Debian package contains a byte-identical copy of the client archive at
`/usr/share/myscoutee-registry/myscoutee-registry-client-tools_<version>.tar.gz`.
It does not install expanded client scripts on the Registry host. Client tools
are extracted and run on the administrative client, never as host lifecycle
commands.

Install the Debian artifact with APT so Docker Engine and Docker Compose v2
dependencies are resolved:

```bash
sudo apt install ./packaging/dist/myscoutee-registry_1.0.0_amd64.deb
```

Installation loads and verifies both bundled images, creates protected
configuration and state directories, and enables the systemd unit. It does not
start or restart the Registry and does not invoke the external deployment
verifier. Review `/etc/myscoutee-registry/registry.env`, install the TLS
certificate and private key named there, then start and qualify explicitly:

```bash
sudo systemctl start myscoutee-registry
sudo /opt/myscoutee-registry/packaging/scripts/qualify-deployment.sh \
  check --expected-version 1.0.0 --timeout-seconds 60
```

SQLite, the Registry signing key, and the VOPRF keyring are bind-mounted from
`/var/lib/myscoutee-registry/data`. Configuration and state survive reinstall,
upgrade, and normal removal. An explicit package purge stops the stack and
removes Registry configuration, state, TLS material, and the two configured
managed images. Make and verify a consistent recovery-unit backup before
purging; package purge never removes an independently stored backup.
