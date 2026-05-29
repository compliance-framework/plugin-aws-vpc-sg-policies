package compliance_framework.deny_open_database_ports

risk_templates := [{
  "name": "Security group allows public database access",
  "title": "Public database service exposure",
  "statement": "A security group allows database ports from public network ranges, increasing the chance of unauthorized access, credential attacks, service abuse, and direct exposure of application data stores.",
  "likelihood_hint": "high",
  "impact_hint": "high",
  "violation_ids": ["sg_open_database_port_access"],
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
    "title": "Restrict public database exposure",
    "description": "Remove public ingress to database ports and allow access only from approved application tiers, administrative networks, or private connectivity paths.",
    "tasks": [
      {"title": "Remove public ingress CIDRs from database port rules in the security group"},
      {"title": "Restrict database access to approved application security groups or private CIDRs"},
      {"title": "Confirm the database is not intended to be directly reachable from the internet"},
      {"title": "Review authentication, encryption, and private connectivity posture for the exposed service"}
    ]
  }
}]

public_source(permission) if {
  cidr := data.public_ipv4_cidrs[_]
  permission.IpRanges[_].CidrIp == cidr
}

database_port(port) if {
  configured_port := data.database_ports[_]
  port == configured_port
}

violation[{"id": "sg_open_database_port_access"}] if {
  permission := input.security_group.IpPermissions[_]
  public_source(permission)
  database_port(permission.ToPort)
}

title := "Database port access should be restricted"
description := "Database ports should not be opened to the wider internet, and should be restricted to trusted sources"
