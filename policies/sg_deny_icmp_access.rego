package compliance_framework.deny_icmp_access

public_source(permission) if {
  cidr := data.public_ipv4_cidrs[_]
  permission.IpRanges[_].CidrIp == cidr
}

icmp_protocol(protocol) if {
  protocol_name := data.icmp_protocols[_]
  protocol == protocol_name
}

violation[{}] if {
  permission := input.security_group.IpPermissions[_]
  public_source(permission)
  icmp_protocol(permission.IpProtocol)
}

title := "ICMP access is restricted"
description := "ICMP access should not be opened to the wider internet, but restricted to validated origins"
