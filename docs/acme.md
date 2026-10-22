# Let's Encrypt and Certbot

## Integration plan

The first integration uses external Certbot issuance/renewal, PEM paths in Balanco, and a systemd deploy hook. No ACME client, DNS credentials or network dependency is added to the proxy. New connections use renewed certificates after a validated SIGHUP reload; established sessions keep running. This recipe targets a Linux host with systemd and one Balanco instance. Fleet publication and a reload-completion API are separate work.

Let's Encrypt supplies the public **server** identity. Device client certificates, upstream client identities and management API allowlists remain under your private PKI; renewal must not replace those trust stores. Public certificates and hybrid TLS key exchange are independent: a normal server certificate can authenticate a hybrid handshake, but its signature remains classical.

## Choose domain validation

Use DNS-01 for wildcard certificates, private listeners, and deployments where Balanco already owns port 443. Certbot updates DNS; no challenge listener or proxy restart is needed. Install Certbot and your DNS plugin using the [official platform instructions](https://certbot.eff.org/instructions).

For Cloudflare, create a token restricted to DNS editing for the required zone. Store `dns_cloudflare_api_token = YOUR_TOKEN` in `/root/.secrets/certbot/cloudflare.ini`, readable only by root (`0600`, parent `0700`). The [plugin guide](https://certbot-dns-cloudflare.readthedocs.io/en/stable/) documents permissions and propagation settings. Neither this file nor its token belongs in Balanco configuration or its management API.

Replace domains and email before running:

```sh
sudo certbot certonly --dns-cloudflare \
  --dns-cloudflare-credentials /root/.secrets/certbot/cloudflare.ini \
  --cert-name devices.example.com \
  -d devices.example.com --email operator@example.com --agree-tos
```

First exercise issuance with `--dry-run`. To include a wildcard, add `-d '*.devices.example.com'`; configure the associated names under Balanco's `tls.sni_certificates` if using multiple identities.

HTTP-01 is an alternative for public DNS names when inbound port 80 is free:

```sh
sudo certbot certonly --standalone --preferred-challenges http \
  --cert-name devices.example.com -d devices.example.com \
  --email operator@example.com --agree-tos
```

Keep port 80 available for renewal too. This does not serve HTTP challenges through Balanco. If another service owns that port, use DNS-01 or Certbot's webroot mode with an existing HTTP server. HTTP-01 does not issue wildcard certificates. No TLS-ALPN-01 responder is included.

## Install the service

Build Balanco as described in the README, then install the binary and service from the repository root. On Debian/Ubuntu, create the service account if it does not already exist:

```sh
sudo useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin balanco
sudo install -m 0755 target/release/balanco /usr/local/bin/balanco
sudo install -d -o root -g balanco -m 0750 /etc/balanco
sudo install -o root -g balanco -m 0640 examples/letsencrypt.json /etc/balanco/balanco.json
sudo install -m 0644 examples/systemd/balanco.service /etc/systemd/system/balanco.service
```

Edit `/etc/balanco/balanco.json` for your domain and backends; install your device CA at `/etc/balanco/device-ca.pem`, readable by `balanco`. The example requires device mTLS and forwards decrypted TCP to loopback origins; add `upstream_tls` as in [mtls.json](../examples/mtls.json) when workloads require TLS. A single identity works without HTTP parsing, including WebSocket byte forwarding. Management API configuration is optional and separate.

Point directly to Certbot's `live` paths, using `fullchain.pem`, not just the leaf certificate. Permit the unprivileged service to traverse Certbot directories and read this lineage's key:

```sh
sudo chmod 0755 /etc/letsencrypt/live /etc/letsencrypt/archive
sudo chgrp balanco /etc/letsencrypt/live/devices.example.com/privkey.pem
sudo chmod 0640 /etc/letsencrypt/live/devices.example.com/privkey.pem
sudo -u balanco /usr/local/bin/balanco --config /etc/balanco/balanco.json --check
sudo systemctl daemon-reload
sudo systemctl enable --now balanco.service
```

Check ancestor/lineage directory permissions if validation reports access denied; do not make private keys world-readable. Certbot preserves modified key group ownership and group mode on renewal; see its [file permissions documentation](https://eff-certbot.readthedocs.io/en/stable/using.html#where-are-my-certificates). Balanco cannot write certificates or configuration under this service's sandbox. Keep `control_socket` under `/run/balanco`; adjust `TimeoutStopSec` if increasing `drain_timeout_ms`.

## Renewal and reload

Install a deploy hook on this host (not a post hook, which can run without a renewed certificate):

```sh
sudo install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
sudo tee /etc/letsencrypt/renewal-hooks/deploy/50-balanco >/dev/null <<'HOOK'
#!/bin/sh
set -eu
# Validate and signal only the service using this successfully renewed lineage.
case "${RENEWED_LINEAGE:-}" in
  /etc/letsencrypt/live/devices.example.com) systemctl reload balanco.service ;;
esac
HOOK
sudo chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/50-balanco
sudo certbot renew --cert-name devices.example.com --dry-run --run-deploy-hooks
```

Use the renewal timer supplied by your Certbot installation; inspect `systemctl list-timers --all` before adding another scheduler. Follow [Certbot's renewal guide](https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates) for other installation methods. Dry-run deploy hooks use the current live certificate, not the temporary staging certificate; this checks the hook path without deploying an untrusted staging identity.

The service's first `ExecReload` validates all configured TLS material as the service user. If it fails, systemd does not execute the subsequent HUP command. Balanco then independently prepares and validates the replacement before publishing it; failures retain the active in-memory configuration. Correct files and retry `systemctl reload balanco.service` after a failure. Do not restart a healthy process to recover from a bad certificate on disk.

HUP publication is asynchronous: successful `systemctl reload` means validation and signal delivery succeeded, not that the running process acknowledged the replacement. Inspect `journalctl -u balanco.service --since '5 minutes ago'` for `configuration generation reloaded for new connections` or a rejection. A full file reload also clears live routing/API overrides; controllers must republish them. Avoid concurrent certificate/configuration changes and verify policy state afterward.

Verify the certificate actually served using a fresh connection with the intended SNI (supply an authorized device certificate/key when mTLS is enabled):

```sh
openssl s_client -connect devices.example.com:443 -servername devices.example.com \
  -cert /secure/device.pem -key /secure/device.key \
  -verify_return_error -verify_hostname devices.example.com </dev/null
sudo openssl x509 -in /etc/letsencrypt/live/devices.example.com/fullchain.pem \
  -noout -serial -dates -fingerprint -sha256
```

Check the live leaf's identity, expiry and fingerprint against the renewed file. Alert on renewal/hook errors and approaching expiry; a failed deployment can leave the old certificate serving until it expires. This integration does not add certificate issuance endpoints, device enrollment, revocation checking or automatic OCSP stapling.
