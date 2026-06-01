package compliance_framework.deny_icmp_access

test_violation_icmp_access if {
  count(violation) == 1 with input as {
    "security_group": {
      "IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "IpProtocol": "icmp"}]
    }
  }
}

test_violation_icmp_access_ipv6 if {
  count(violation) == 1 with input as {
    "security_group": {
      "IpPermissions": [{"Ipv6Ranges": [{"CidrIpv6": "::/0"}], "IpProtocol": "icmp"}]
    }
  }
}
