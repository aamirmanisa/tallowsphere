# Next-rebuild checklist (server reprovision)

Carried from the 2026-09-17 cryptographic posture audit (finding F3: root disk
not LUKS-encrypted — accepted for now because every sensitive set on the disk
is individually encrypted; closes at the next reprovision).

- [ ] LUKS-encrypt the root volume at reprovision (encrypt-at-install), or move
      `/home` + `/var/backups` onto a LUKS data volume if in-place is not viable.
- [ ] Re-verify at-rest state: dm-crypt swap (`/etc/crypttab` → `cryptswap`),
      age-encrypted backup sets (`/var/backups/vault`, `/var/backups/repos`,
      `/var/backups/tallow-relay`), keyring encryption (Argon2id).
- [ ] Confirm `/etc/tallow-relay/backup-age.key` has an offline copy outside
      this box — without it every `.age` backup set is unrecoverable.
- [ ] Re-apply crypto policy: sshd MACs drop-in (`99-opsec-macs.conf`), Caddy
      log format filter (IP scrubbing), host-firewall.service default-deny
      (22/80/443 + 3478 + 4433-4435 + TURN relay range).
- [ ] Rebuild `tallow-relay` (stage2-wire) and re-run: browser e2e both modes,
      relay-only mode, CLI ladder smokes, strict-TLS live test
      (`cargo test -p tallow-net --no-default-features --features quic --test
      live_relay_tls -- --ignored`).

Delete this file once LUKS is in place.
