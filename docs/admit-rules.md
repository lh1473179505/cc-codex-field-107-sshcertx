# sshcertx admit rules

## Signing input

Certificates sign (ASCII, no spaces beyond those inside field values
that docs forbid):

`v1|{ca_kid}|{key_id}|{principals_csv}|{force_command}|{source_address}|{valid_after}|{valid_before}`

HMAC-SHA256 over that line with the hex-decoded key secret, then
base64url without `=` padding. The engine always recomputes the signing
line from the certificate itself; a supplied `_sign_line` is an
untrusted hint and is never relied upon.

## Interacting gates

Gates are evaluated in this order and every failing gate contributes its
reason code:

1. key: unknown CA kid -> `ca_unknown`; revoked CA kid -> `ca_revoked`
   (even when the HMAC itself verifies)
2. signature: recomputed HMAC mismatch -> `bad_signature`
3. principals 与 policy.allowed_principals 求交非空 -> `principal_denied`
4. force-command 必须 exact 命中 policy.allowed_force_commands，或为空且
   policy.allow_interactive -> `force_command_denied`
5. source-address CIDR 必须覆盖连接来源（client_address）->
   `source_denied`；来源缺失则 `source_required`
6. 时间窗：now 早于 valid_after（含 clock_skew_seconds 容差）->
   `not_yet_valid`；now 晚于 valid_before -> `expired`
7. serial 重放：serial 已记录在 store -> `serial_replay`；only an allow
   writes the serial, a deny never mutates the store

The decision is `allow` only when no gate fails; `reason_codes` is then
`[]`.

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-login, ok-forced

Deny cases: bad-sig, principal, force-cmd, source, revoked, replay, expired, early

Reason codes should be stable snake_case identifiers matching the failing gate.
