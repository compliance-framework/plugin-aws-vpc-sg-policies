package compliance_framework.deny_open_database_ports

test_violation_open_database_ports if {
  count(violation) == 1 with input as {
    "security_group": {
      "IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "ToPort": 3306}]
    }
  }
}