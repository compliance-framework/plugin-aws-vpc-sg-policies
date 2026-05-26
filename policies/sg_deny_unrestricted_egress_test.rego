package compliance_framework.deny_unrestricted_egress

test_violation_unrestricted_egress if {
  count(violation) == 1 with input as {
    "security_group": {
      "IpPermissionsEgress": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    }
  }
}