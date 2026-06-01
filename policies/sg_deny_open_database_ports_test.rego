package compliance_framework.deny_open_database_ports

test_violation_open_database_ports if {
  count(violation) == 1 with input as {
    "security_group": {
      "IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "ToPort": 3306}]
    }
  }
}

test_violation_open_database_ports_range if {
  count(violation) == 1 with input as {
    "security_group": {
      "IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "FromPort": 3200, "ToPort": 3400}]
    }
  }
}

test_violation_open_database_ports_ipv6 if {
  count(violation) == 1 with input as {
    "security_group": {
      "IpPermissions": [{"Ipv6Ranges": [{"CidrIpv6": "::/0"}], "ToPort": 3306}]
    }
  }
}
