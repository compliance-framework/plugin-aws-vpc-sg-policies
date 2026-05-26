package compliance_framework.deny_open_rdp

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

violation[{}] if {
  permission := input.security_group.IpPermissions[_]
  public_source(permission)
  rdp_port_exposed(permission)
}

title := "RDP access should be restricted"
description := "RDP access should not be open to the wider internet, and should be limited to trusted sources"
