package compliance_framework.deny_permissive_cidr

violation[{}] if {
  cidr := data.permissive_ingress_ipv4_cidrs[_]
  input.security_group.IpPermissions[_].IpRanges[_].CidrIp == cidr
}

title := "CIDR Ingress should be restricted"
description := "Ingress should be limited to trusted CIDRs and not opened to the wider internet"
