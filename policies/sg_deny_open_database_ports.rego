package compliance_framework.deny_open_database_ports

public_source(permission) if {
  cidr := data.public_ipv4_cidrs[_]
  permission.IpRanges[_].CidrIp == cidr
}

database_port(port) if {
  configured_port := data.database_ports[_]
  port == configured_port
}

violation[{}] if {
  permission := input.security_group.IpPermissions[_]
  public_source(permission)
  database_port(permission.ToPort)
}

title := "Database port access should be restricted"
description := "Database ports should not be opened to the wider internet, and should be restricted to trusted sources"
