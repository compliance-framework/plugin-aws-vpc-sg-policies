package compliance_framework.flag_self_referencing_rules

test_violation_self_referencing_ingress if {
  count(violation) == 1 with input as {
    "security_group": {
      "GroupId": "sg-123",
      "IpPermissions": [{"UserIdGroupPairs": [{"GroupId": "sg-123"}]}],
      "IpPermissionsEgress": []
    }
  }
}

test_violation_self_referencing_egress if {
  count(violation) == 1 with input as {
    "security_group": {
      "GroupId": "sg-123",
      "IpPermissions": [],
      "IpPermissionsEgress": [{"UserIdGroupPairs": [{"GroupId": "sg-123"}]}]
    }
  }
}

test_no_violation_for_peer_reference if {
  count(violation) == 0 with input as {
    "security_group": {
      "GroupId": "sg-123",
      "IpPermissions": [{"UserIdGroupPairs": [{"GroupId": "sg-456"}]}],
      "IpPermissionsEgress": []
    }
  }
}
