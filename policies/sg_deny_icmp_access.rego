package compliance_framework.deny_icmp_access

risk_templates := [{
  "name": "Security group allows public ICMP access",
  "title": "Public ICMP exposure",
  "statement": "A security group allows ICMP traffic from public network ranges, enabling unsolicited network probing, host discovery, and reconnaissance against the attached workload or service boundary.",
  "likelihood_hint": "medium",
  "impact_hint": "medium",
  "violation_ids": ["sg_public_icmp_access"],
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
    "title": "Restrict public ICMP exposure",
    "description": "Limit ICMP ingress to approved diagnostic paths or internal networks and remove broad public reachability where it is not required.",
    "tasks": [
      {"title": "Remove public ICMP ingress CIDRs from the security group"},
      {"title": "Restrict ICMP to approved internal networks or controlled diagnostic sources"},
      {"title": "Review whether external ping or ICMP diagnostics are operationally necessary"}
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

icmp_protocol(protocol) if {
  protocol_name := data.icmp_protocols[_]
  protocol == protocol_name
}

violation[{"id": "sg_public_icmp_access"}] if {
  permission := input.security_group.IpPermissions[_]
  public_source(permission)
  icmp_protocol(permission.IpProtocol)
}

title := "ICMP access is restricted"
description := "ICMP access should not be opened to the wider internet, but restricted to validated origins"
