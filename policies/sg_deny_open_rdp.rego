package compliance_framework.deny_open_rdp

risk_templates := [{
  "name": "Security group allows public RDP access",
  "title": "Public RDP administrative access exposure",
  "statement": "A security group allows RDP access from public network ranges, exposing remote administrative access to unauthorized scanning, password attacks, and direct compromise opportunities.",
  "likelihood_hint": "high",
  "impact_hint": "high",
  "violation_ids": ["sg_open_rdp_access"],
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-284",
      "title": "Improper Access Control",
      "url": "https://cwe.mitre.org/data/definitions/284.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-668",
      "title": "Exposure of Resource to Wrong Sphere",
      "url": "https://cwe.mitre.org/data/definitions/668.html"
    }
  ],
  "remediation": {
    "title": "Restrict public RDP exposure",
    "description": "Limit RDP ingress to approved management networks or controlled remote administration paths and remove broad public exposure from the security group.",
    "tasks": [
      {"title": "Remove public IPv4 and IPv6 RDP ingress ranges from the security group"},
      {"title": "Restrict RDP to approved management CIDRs, bastions, or remote access gateways"},
      {"title": "Review whether direct RDP access is required for the workload"},
      {"title": "Confirm administrative access is routed through approved and monitored entry points"}
    ]
  }
}]

public_source(permission) if {
  cidr := data.public_ipv4_cidrs[_]
  permission.IpRanges[_].CidrIp == cidr
}

public_source(permission) if {
  cidr := data.public_ipv6_cidrs[_]
  permission.Ipv6Ranges[_].CidrIpv6 == cidr
}

rdp_port_exposed(permission) if {
  port := data.rdp_ports[_]
  permission.ToPort == port
}

rdp_port_exposed(permission) if {
  port := data.rdp_ports[_]
  permission.FromPort <= port
  permission.ToPort >= port
}

violation[{"id": "sg_open_rdp_access"}] if {
  permission := input.security_group.IpPermissions[_]
  public_source(permission)
  rdp_port_exposed(permission)
}

title := "RDP access should be restricted"
description := "RDP access should not be open to the wider internet, and should be limited to trusted sources"
