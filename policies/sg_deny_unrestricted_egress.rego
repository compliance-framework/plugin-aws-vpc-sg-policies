package compliance_framework.deny_unrestricted_egress

violation[{}] if {
  cidr := data.unrestricted_egress_ipv4_cidrs[_]
  input.security_group.IpPermissionsEgress[_].IpRanges[_].CidrIp == cidr
}

title := "Egress should be restricted"
description := "Egress rules should be limited to trusted CIDRs and not opened to the wider internet"
