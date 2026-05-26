package compliance_framework.deny_open_ssh

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

violation[{}] if {
  permission := input.security_group.IpPermissions[_]
  public_source(permission)
  ssh_port_exposed(permission)
}

title := "SSH access should be restricted"
description := "SSH access should not be open to the wider internet, and should be limited to trusted sources"
