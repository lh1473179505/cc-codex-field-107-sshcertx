# sshcertx admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{ca_kid}|{key_id}|{principals_csv}|{force_command}|{source_address}|{valid_after}|{valid_before}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- principals 与 policy.allowed_principals 求交非空
- force-command 必须 exact 命中允许表，或为空且 policy.allow_interactive
- source-address CIDR 必须覆盖连接来源；来源缺失则 source_required
- CA kid 吊销、时间窗、serial 重放

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-login, ok-forced

Deny cases: bad-sig, principal, force-cmd, source, revoked, replay, expired, early

Reason codes should be stable snake_case identifiers matching the failing gate.
