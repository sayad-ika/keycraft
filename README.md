# keycraft

`keycraft` is a local-first, offline CLI password manager.

## Guarantees

- Local-only storage (single encrypted vault file on disk)
- No cloud sync
- No telemetry
- No network calls in runtime logic

## Security model

- Vault data is encrypted with `AES-256-GCM`
- Key derivation uses `PBKDF2-SHA256` (`210,000` iterations, per-vault random salt)
- Master password is never written to disk
- Wrong master password fails decryption/authentication

The vault file is JSON metadata + encrypted ciphertext payload.

## Build

```bash
go build ./...
```

Binary entrypoint:

- `cmd/keycraft/main.go`

## Usage

```bash
keycraft init
keycraft add --service github --username alice
keycraft list
keycraft get --service github --username alice --show-password
keycraft update --id <entry-id> --password -
keycraft delete --id <entry-id>
keycraft generate --length 32
keycraft change-master
keycraft backup
keycraft audit --fail-on-issues
keycraft version
```

Default vault path:

- `~/.keycraft/vault.json`

Override with `--vault` on commands, or set `KEYCRAFT_VAULT` for a default custom path.

## Commands

- `init`: create a new encrypted vault
- `add`: add one entry
- `list`: list entries (`--search` supported)
- `get`: fetch one entry by `--id` or `--service` + optional `--username`
- `update`: update fields for an entry (`--id` required)
- `delete`: delete entry (`--id` required, prompt unless `--force`)
- `generate`: generate strong random password
- `change-master`: rotate master password and re-encrypt vault
- `backup`: create timestamped encrypted backup of the vault file
- `audit`: detect weak, reused, stale, duplicate, and malformed entries
- `version`: print CLI version

## Additional examples

```bash
# write backup to default location: ~/.keycraft/backups/vault-<timestamp>.json
keycraft backup

# write backup to custom path
keycraft backup --out ./vault-backup.json

# enforce policy in CI/local checks (non-zero exit when issues exist)
keycraft audit --min-length 14 --max-age-days 365 --fail-on-issues
```
