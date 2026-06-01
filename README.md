# AWS VPC security group policies

Standalone OPA/Rego policy bundle for security group evidence emitted by the `plugin-aws-vpc` collector.

## Input schema

Each policy evaluates one security group at a time using:

- `input.security_group`
- `input.sg_context`

Current security-group context includes the parent VPC, other security groups in the VPC, attached network interfaces, attached subnets, route tables, related network ACLs, internet gateways, VPC endpoints, related flow logs, related log groups, and transit gateway attachments.

## Current coverage

This bundle currently checks security-group posture such as:

- required security group tags
- open SSH access
- open RDP access
- open database ports
- ICMP access from public sources
- permissive ingress CIDRs
- unrestricted egress CIDRs
- default security group usage
- orphaned security groups
- missing peer security group references
- self-referencing rules
- public ingress on internet-routable attached workloads

## Policy data

Default baselines live in `policies/data.json` and can be overridden by agent-supplied policy data. Current settings cover required tags, public IPv4 and IPv6 CIDRs, SSH and RDP ports, database ports, ICMP protocols, permissive ingress CIDRs, and unrestricted egress CIDRs.

## Testing

Run local checks with:

```shell
opa check policies
opa test policies
```

Or use the Makefile wrappers:

```shell
make validate
make test
```

## Bundling

Build the distributable bundle with:

```shell
make build
```

This writes `dist/bundle.tar.gz`.
