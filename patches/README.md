# Patches

Local workarounds for upstream bugs this project hits, until they're merged
upstream. Each `.patch` applies cleanly to a fresh clone of the upstream repo
named in its filename.

## `opa-provider-local-dev-and-multi-target.patch`

Applies to [`complytime/complytime-providers`](https://github.com/complytime/complytime-providers)
(tested against its `main` branch). Fixes two bugs in `opa-provider` v0.3.0
that this project's two-evaluator-per-policy setup (`ampel` for AR01, `opa`
for AR02) hits in practice:

1. `conftest pull` (used internally by `opa-provider` to fetch the OPA/Rego
   bundle) has no plain-HTTP/insecure-TLS passthrough at all, unlike
   `conftest push` or complyctl's own `policies[].url`. Adds the same
   `http://`-prefix convention complyctl already uses.
2. `Generate` hard-fails for a target that has neither a `complypack` nor an
   `opa_bundle_ref` variable, instead of skipping gracefully the way
   `ampel-provider` already does for its own analogous "nothing to do" case.
   `Generate` is invoked once per (evaluator, target) pair with no awareness
   of which evaluator a target actually uses, so this blocks any policy that
   splits evaluators across targets (see `.complytime/complytime.yaml`'s
   comments).

Not yet submitted upstream — parked per `CLAUDE.md`'s "contribute upstream"
rule. Apply and build with:

```bash
git clone https://github.com/complytime/complytime-providers.git /tmp/complytime-providers
cd /tmp/complytime-providers
git apply /path/to/rosa-seaplane-compliance/patches/opa-provider-local-dev-and-multi-target.patch
go build -o "$(go env GOPATH)/bin/opa-provider" ./cmd/opa-provider
```

See `docs/credentials.md`'s OCI registry section and the top-level README's
full local-run walkthrough for how this fits into the rest of the setup.
