package compliance_framework.deny_permissive_cidr

risk_templates := [{
  "name": "Security group allows overly broad ingress CIDRs",
  "title": "Overly broad ingress exposure",
  "statement": "A security group uses ingress CIDR ranges that are broad enough to expose the protected service boundary to large parts of the internet, increasing the likelihood of unauthorized access, scanning, and service abuse.",
  "likelihood_hint": "high",
  "impact_hint": "high",
  "violation_ids": ["sg_permissive_ingress_cidr"],
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
    "title": "Reduce ingress CIDR scope",
    "description": "Replace overly broad ingress CIDR ranges with narrowly scoped trusted sources that match the intended access pattern for the workload.",
    "tasks": [
      {"title": "Remove permissive public ingress CIDRs from the security group"},
      {"title": "Allow only approved source networks, security groups, or private access paths"},
      {"title": "Review whether the exposed service should be internet-facing at all"}
    ]
  }
}]

violation[{"id": "sg_permissive_ingress_cidr"}] if {
  cidr := data.permissive_ingress_ipv4_cidrs[_]
  input.security_group.IpPermissions[_].IpRanges[_].CidrIp == cidr
}

violation[{"id": "sg_permissive_ingress_cidr"}] if {
  cidr := data.permissive_ingress_ipv6_cidrs[_]
  input.security_group.IpPermissions[_].Ipv6Ranges[_].CidrIpv6 == cidr
}

title := "CIDR Ingress should be restricted"
description := "Ingress should be limited to trusted CIDRs and not opened to the wider internet"
