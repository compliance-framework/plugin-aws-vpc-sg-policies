package compliance_framework.deny_open_rdp

test_violation_open_rdp if {
  count(violation) == 1 with input as {
    "security_group": {
      "IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "ToPort": 3389}]
    }
  }
}
