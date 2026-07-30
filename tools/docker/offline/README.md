# MyScoutee Registry offline stack

The generated bundle deploys two separate containers: the non-root Go registry and its
Nginx TLS edge. It does not contain source code, a build context, a certificate,
a TLS private key, a registry signing key, a VOPRF keyring, a database, or a
production environment file. The included Nginx template is an audit copy; the
same template is already embedded in the edge image.

Verify the release checksum or detached vendor signature received through the
approved release channel before loading either image. `SHA256SUMS` detects
damage inside an already trusted bundle; it is not an authenticity proof by
itself.

```bash
sha256sum --check SHA256SUMS
docker image load --input images/myscoutee-registry.tar
docker image load --input images/myscoutee-registry-edge.tar
docker image inspect myscoutee-registry:1.0.0-prod \
  --format '{{.Id}} {{.Os}}/{{.Architecture}}'
docker image inspect myscoutee-registry-edge:1.0.0-prod \
  --format '{{.Id}} {{.Os}}/{{.Architecture}}'
```

Compare the two reported image IDs with `IMAGE-MANIFEST.json`. Install the TLS
pair separately, copy `registry.env.example` to a protected location, and set
the real scope, hostname, bind address, and absolute TLS paths.

```bash
sudo install -d -m 0700 /opt/myscoutee-registry/tls
sudo install -o root -g root -m 0600 /secure/source/fullchain.pem \
  /opt/myscoutee-registry/tls/fullchain.pem
sudo install -o root -g root -m 0600 /secure/source/privkey.pem \
  /opt/myscoutee-registry/tls/privkey.pem
sudo install -m 0600 registry.env.example /etc/myscoutee-registry.env
sudoedit /etc/myscoutee-registry.env

docker compose --env-file /etc/myscoutee-registry.env \
  -f compose.yaml config --quiet
docker compose --env-file /etc/myscoutee-registry.env \
  -f compose.yaml up --pull never -d
docker compose --env-file /etc/myscoutee-registry.env \
  -f compose.yaml ps
```

Both services must become healthy. Validate the public certificate and
`/v1/registry/identity` from a separate client. Back up the SQLite database,
registry signing key, and VOPRF keyring as one consistent recovery unit. The
target host needs Docker Engine and Docker Compose but no Go compiler, GitHub,
Docker Hub, source checkout, or outbound network access.
