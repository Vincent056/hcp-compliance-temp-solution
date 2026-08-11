# OAuth Token Max Age: full OR-semantics CustomRule (server OR every client)

Closes the gap flagged in the coverage analysis: the mgmt-side CEL rule
`hcp-oauth-token-maxage` covers only the OAuth SERVER half
(`HostedCluster.spec.configuration.oauth.tokenConfig`), while the original
`oauth_or_oauthclient_token_maxage` OpenSCAP rule has OR semantics - compliant if
the server sets `tokenConfig.accessTokenMaxAgeSeconds`, OR every `OAuthClient`
sets its own `accessTokenMaxAgeSeconds` (client settings override the server; the
OVAL requires at least one client to exist for the client half).

`customrule.yaml` implements the faithful OR semantics in CEL with two inputs
(`oauths/cluster` + `oauthclients`, threshold 28800s / 8h per the STIG variable).

**Deployment scope:** OAuthClient objects are served by the cluster's own API -
they are NOT visible from the management cluster. Deploy this rule on the cluster
whose OAuth posture it should assess: inside a hosted cluster (with workers) for
hosted-cluster compliance, or on any standalone/management cluster. The mgmt-side
`hcp-oauth-token-maxage` (HostedCluster source of truth) remains the authoritative
server-half check for hosted clusters and is intentionally stricter (no OR).

## Validation (2026-08-10, CO v1.9.1, OCP 4.21.28)

- `celctl cac lint` OK; **`cac test` 7/7 cases** — server-set PASS, all-clients-set
  PASS, one-client-missing FAIL, both-unset FAIL, server-over-threshold FAIL,
  zero-clients FAIL (existence semantics), client-over-threshold FAIL.
- **Live, both directions** (rule deployed on the 4.21.28 cluster): unconfigured
  OAuth + system clients without max age -> scan FAIL; `oauths/cluster` patched to
  `accessTokenMaxAgeSeconds: 28800` -> rescan PASS; config reverted afterwards.
  CustomRule `Ready` at admission; no extra RBAC needed (cluster-reader covers
  `oauthclients`).
