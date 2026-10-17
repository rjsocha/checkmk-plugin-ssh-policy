# checkmk-plugin-ssh-policy

Checkmk check that compares the SSH keys deployed on a host with the keys
its host policy allows.

The agent plugin `ssh-policy` (package `check-mk-agent-push`) sends one line
per user of `/etc/ssh-pool`: user, host name and the SHA-256 of every key
line. The check rebuilds the same hashes from the policy and reports one
service per user, `SSH Key for <user>`.

## Policy tree

```
<root>/current/<group>/<host>.yaml   host policy
<root>/current/<group>/default.yaml  append.user of the group, optional
<root>/key/<group>/<key>             public keys named in authorized
```

Groups are the directories under `<root>/current`; a host must have a policy
in one group only. The root is `/opt/policy`, or `policy.root` of
`/etc/site/checkmk-plugin-ssh-policy/config.yaml`.

## States

| State | When |
| --- | --- |
| OK | keys on the host match the policy |
| WARN | keys missing on the host or extra keys on the host |
| CRIT | no policy file for the host, or no entry for the host in it |
| UNKNOWN | unreadable policy, policy in several groups, key file not found |
