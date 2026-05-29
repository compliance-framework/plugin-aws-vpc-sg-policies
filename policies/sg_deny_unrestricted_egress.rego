package compliance_framework.deny_unrestricted_egress

risk_templates := [{
  "name": "Security group allows unrestricted egress",
  "title": "Unrestricted outbound network exposure",
  "statement": "A security group allows unrestricted outbound traffic to broad public network ranges, increasing the chance of uncontrolled data transfer, command-and-control reachability, and weak outbound boundary enforcement.",
  "likelihood_hint": "medium",
  "impact_hint": "high",
  "violation_ids": ["sg_unrestricted_egress"],
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
    "title": "Restrict outbound network access",
    "description": "Replace unrestricted outbound rules with the minimum required destinations, services, or approved egress paths for the workload.",
    "tasks": [
      {"title": "Remove unrestricted public egress CIDRs from the security group"},
      {"title": "Restrict outbound access to approved destinations, ports, or service endpoints"},
      {"title": "Review whether outbound traffic should be routed through managed egress controls or inspection points"}
    ]
  }
}]

violation[{"id": "sg_unrestricted_egress"}] if {
  cidr := data.unrestricted_egress_ipv4_cidrs[_]
  input.security_group.IpPermissionsEgress[_].IpRanges[_].CidrIp == cidr
}

title := "Egress should be restricted"
description := "Egress rules should be limited to trusted CIDRs and not opened to the wider internet"
