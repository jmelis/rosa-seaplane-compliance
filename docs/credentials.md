# Credentials

Every credential this project uses should be scoped to exactly what the
thing consuming it does — not a personal admin token, not a shared
all-access secret. This doc is where to look before running evidence
collection, a scan, or a push to the evidence locker, and where to add a
section when a new evidence source shows up.

## GitHub (`GITHUB_TOKEN`)

Used by:
- `evidence/RSC.CMT.CTRL01.AR01.sh` — `gh api repos/{repo}/branches/{branch}/protection`
- `evidence/RSC.CMT.CTRL01.AR02.sh` — a GraphQL query over merged PRs
- the `ampel` evaluator's `access_token` target variable (`.complytime/complytime.yaml`)

Don't reuse your personal `gh auth token` for this — it carries whatever
scopes your day-to-day admin session has. Create a token scoped to just this
job instead.

**Fine-grained PAT (preferred):**

1. GitHub → **Settings → Developer settings → Personal access tokens →
   Fine-grained tokens → Generate new token**
2. **Token name:** something identifiable, e.g. `rosa-seaplane-compliance-evidence`
3. **Resource owner:** `openshift-online` (the org that owns `rosa-seaplane`)
4. **Expiration:** short-lived (e.g. 90 days) — this is a bot-style
   credential, rotate it rather than making it permanent
5. **Repository access:** "Only select repositories" → `rosa-seaplane` only
   (add other repos here only once a collector actually reads from them)
6. **Permissions → Repository permissions:**
   - Administration: **Read-only** (branch-protection reads are gated
     behind admin-read, not plain repo read)
   - Pull requests: **Read-only**
   - Metadata: Read-only (auto-included, can't be unchecked)
   - Leave everything else "No access"
7. Generate, copy the token (`github_pat_...`)

If the org restricts or blocks fine-grained PATs, fall back to a **classic
PAT** with just the `repo` scope (classic tokens can't scope to a single
repo or to read-only admin, so `repo` is the minimum that still works for
branch-protection reads).

**Wiring it in:** set it in `.envrc` (already `.gitignore`d):

```bash
export GITHUB_TOKEN=github_pat_xxxxxxxx
```

then `direnv allow`. `gh api` prefers `GITHUB_TOKEN`/`GH_TOKEN` over its own
stored keyring credential automatically, so nothing else needs to change —
not even your own `gh auth login` session.

## S3 evidence locker (`RSC_S3_BUCKET`, AWS credentials)

Used by `scripts/push-evidence.sh` (`make push-evidence`) to upload
`evidence/output/` and `.complytime/scan/` to the shared evidence locker.

Needs standard AWS credentials (env vars, a profile, or an assumed role —
whatever `aws` CLI already resolves) with write access to the target
bucket, plus:

```bash
export RSC_S3_BUCKET=<bucket-name>
# export RSC_S3_PREFIX=<prefix>          # optional, defaults to rosa-seaplane-compliance
```

**Local development** (no real AWS account needed) — run a disposable
S3-compatible endpoint and point `push-evidence.sh` at it:

```bash
podman run -d --name local-s3 -p 9090:9090 docker.io/adobe/s3mock:latest
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1
aws --endpoint-url http://localhost:9090 s3 mb s3://rosa-seaplane-evidence
export RSC_S3_BUCKET=rosa-seaplane-evidence RSC_S3_ENDPOINT_URL=http://localhost:9090
```

These `test`/`test` values aren't real secrets — they're s3mock's
no-op local credentials, fine to keep in a shell history or a local
`.envrc`. Never do this against real AWS.

## OCI registry — not evidence collection, but part of the pipeline

`make publish-policy` / `make publish-opa-bundle` push the Gemara policy and
OPA/Rego bundles to `REGISTRY` (`Makefile`). **This defaults to a local-only
registry, not a public one** — nothing is published anywhere public unless
you explicitly repoint `REGISTRY` at one and authenticate to it yourself
(e.g. `podman login your-registry.example.com`). Publishing to a public
registry is a deliberate, manual action, not something to automate casually.

**Local registry** (the default — start it once, then `make publish-policy`
and `make publish-opa-bundle` work as-is):

```bash
podman run -d --name local-oci-registry -p 5050:5000 docker.io/library/registry:2
```

`REGISTRY`'s `http://` prefix is how both publish scripts and
`.complytime/complytime.yaml` opt into plain-HTTP for this local registry —
`scripts/publish-policy-bundle.sh`/`publish-opa-bundle.sh` strip it and pass
`--plain-http`/`--tls=false` to `oras`/`conftest` respectively; complyctl
itself detects the same prefix on `policies[].url`
(`internal/registry/client.go`'s `NewClient`) and strips it before building
the actual OCI reference. There's no `plain-http: true` field on a
`policies[]` entry — that key belongs to complypack.yaml's schema, not
complyctl's.

Pulling the opa/Rego bundle has one remaining rough edge: as shipped in
`complytime-providers` v0.3.0, `opa-provider`'s own `conftest pull` call
(`constructConftestPullCommand`) has **no way to pass `--tls=false` at
all** — a real gap, not a configuration problem (pushing is fine; `conftest
push` has always had the flag). We patched a local `complytime-providers`
checkout to support the same `http://`-prefix convention as complyctl for
`opa_bundle_ref`; that patch isn't upstream yet (parked, see
`project_complypack-upstream-issue-parked.md`-style follow-up). Until it
merges, running `complyctl scan` against the local registry needs a build of
`opa-provider` from that patched fork, not the stock release — `complyctl
get`/publishing work fine with the stock release either way.

**Pointing at a real registry later:** change `REGISTRY`/`IMAGE_REGISTRY` in
`Makefile` and the two refs in `.complytime/complytime.yaml` together (drop
the `http://` prefix for a real TLS registry), then run `make publish-policy`
/ `make publish-opa-bundle` from an authenticated session.

## Adding a new evidence source

When a new `evidence/*.sh` collector needs a credential:

1. Scope it as narrowly as the source allows — read-only, limited to the
   specific repo/resource/API the collector actually touches, short-lived
   if the source supports expiry.
2. Name its env var `RSC_<SOURCE>_<THING>` (matching the `RSC_*` convention
   already used by `RSC_REPO`, `RSC_S3_BUCKET`, etc.).
3. Add a section here: what it's used by, exactly how to mint the minimal
   version of it, and how to wire it into `.envrc`.
4. If local development without the real credential is possible (a mock
   server, a sandbox account), document that too — see the S3 and OCI
   registry sections above for the pattern.
