package compliance_framework.deny_permissive_cidr

test_violation_permissive_cidr if {
  count(violation) == 1 with input as {
    "security_group": {
      "IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    }
  }
}

test_violation_permissive_cidr_2 if {
  count(violation) == 1 with input as {
    "security_group": {
      "IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/1"}]}]
    }
  }
}

test_violation_permissive_cidr_3 if {
  count(violation) == 1 with input as {
    "security_group": {
      "IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/2"}]}]
    }
  }
}

test_violation_permissive_cidr_ipv6 if {
  count(violation) == 1 with input as {
    "security_group": {
      "IpPermissions": [{"Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]
    }
  }
}
