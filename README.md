# labtris-network-skills

Protocol analysis rules, fault-injection playbooks, device command sets and
prompts for the Labtris assistant. Loaded from git at startup, so the
content changes without redeploying a Labtris server.

## Why this exists separately

Skills are content, not code. They change far more often than the server
does, they are the part a network engineer can contribute to without
touching Python, and they are worth versioning on their own.

## Licensing — read before contributing

**MIT.** Everything here must be original or MIT-compatible.

GNS3 ships a comparable repository, `GNS3/gns3-skills`, under **GPL-3.0**.
It is good work and worth reading. **Do not copy from it.** Labtris core is
MIT and the cloud emulator is commercial; GPL-3.0 content cannot live in
either. Same rule as vendor images: we reference, we do not redistribute.

If a rule here looks like theirs because both describe the same protocol,
that is convergence on what BGP actually puts on the wire. If you copied,
say so in the PR and it will be rejected — that is cheaper than finding out
later.

## Layout

| Directory | What it holds |
|---|---|
| `packet_analysis/` | One file per protocol: display filter plus the tshark fields that matter |
| `injection/` | One file per fault family: what to break, how, and what the learner should see |
| `device/` | Per-platform command sets, so the assistant knows how to ask a device a question |
| `prompts/` | System prompts the assistant can be run with |
| `config/` | Command security — what the assistant may and may not execute |

## Field names are verified, not guessed

Every `tshark_field` in this repo exists in the dissector. Check before
adding one:

```bash
tshark -G fields | awk -F'\t' '$1=="F"{print $3}' | grep -x 'bgp.notify.major_error'
```

A rule naming a field that does not exist produces an empty column and an
assistant that confidently reports nothing is wrong. Verified against
tshark 4.2.2.

## What Labtris covers that a general network-skills repo does not

`packet_analysis/roce_v2.yaml`, `uet.yaml`, `ecn_marking.yaml` and
`pfc.yaml` exist because Labtris runs RDMA over soft-RoCE, puts Ultra
Ethernet frames on the wire, and marks ECN with a real RED qdisc under an
eight-band priority tree. Those are the labs nobody else can run, so they
are the rules nobody else has written.

`pfc.yaml` is a special case worth reading: its first check is that the
filter matches *nothing*, because Labtris ships the queueing half of
802.1Qbb and does not emit PAUSE frames. A rule that explains an absence
is still a rule — it stops someone concluding their lab is broken.

## Coverage, honestly

GNS3's repository has 61 protocol rules and 51 fault families. This one has
six and four. On breadth we are nowhere, and a contributor should know that
going in rather than discover it.

Where this repository is not behind is the part that comes from what
Labtris can actually run: RoCEv2, Ultra Ethernet, ECN under queue pressure
and PFC. Those cannot be written against an emulator that has no RDMA, no
UET stack and no priority queueing, which is why they do not exist
elsewhere. Breadth is a matter of time; those four are a matter of what the
platform underneath can do.
