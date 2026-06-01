package compliance_framework.deny_open_ssh

risk_templates := [{
  "name": "Security group allows public SSH access",
  "title": "Public SSH administrative access exposure",
  "statement": "A security group allows SSH access from public network ranges, exposing administrative remote access paths to unauthorized probing, brute-force attempts, and direct compromise if credentials or keys are misused.",
  "likelihood_hint": "high",
  "impact_hint": "high",
  "violation_ids": ["sg_open_ssh_access"],
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
    "title": "Restrict public SSH exposure",
    "description": "Limit SSH ingress to approved management networks or controlled access paths and remove broad public exposure from the security group.",
    "tasks": [
      {"title": "Remove public IPv4 and IPv6 SSH ingress ranges from the security group"},
      {"title": "Restrict SSH to approved management CIDRs, bastions, or access proxies"},
      {"title": "Review whether the workload requires direct SSH access at all"},
      {"title": "Confirm administrative access paths are monitored and managed through approved entry points"}
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

ssh_port_exposed(permission) if {
  port := data.ssh_ports[_]
  permission.ToPort == port
}

ssh_port_exposed(permission) if {
  port := data.ssh_ports[_]
  permission.FromPort <= port
  permission.ToPort >= port
}

violation[{"id": "sg_open_ssh_access"}] if {
  permission := input.security_group.IpPermissions[_]
  public_source(permission)
  ssh_port_exposed(permission)
}

title := "SSH access should be restricted"
description := "SSH access should not be open to the wider internet, and should be limited to trusted sources"
