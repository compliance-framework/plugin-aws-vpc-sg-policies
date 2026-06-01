package compliance_framework.deny_orphaned_group_references

test_violation_orphaned_ingress_reference if {
  count(violation) == 1 with input as {
    "security_group": {
      "GroupId": "sg-current",
      "IpPermissions": [{"UserIdGroupPairs": [{"GroupId": "sg-missing"}]}],
      "IpPermissionsEgress": []
    },
    "sg_context": {
      "security_groups_in_vpc": [
        {"GroupId": "sg-current"},
        {"GroupId": "sg-peer"}
      ]
    }
  }
}

test_violation_orphaned_egress_reference if {
  count(violation) == 1 with input as {
    "security_group": {
      "GroupId": "sg-current",
      "IpPermissions": [],
      "IpPermissionsEgress": [{"UserIdGroupPairs": [{"GroupId": "sg-missing"}]}]
    },
    "sg_context": {
      "security_groups_in_vpc": [
        {"GroupId": "sg-current"},
        {"GroupId": "sg-peer"}
      ]
    }
  }
}

test_no_violation_existing_reference if {
  count(violation) == 0 with input as {
    "security_group": {
      "GroupId": "sg-current",
      "IpPermissions": [{"UserIdGroupPairs": [{"GroupId": "sg-peer"}]}],
      "IpPermissionsEgress": []
    },
    "sg_context": {
      "security_groups_in_vpc": [
        {"GroupId": "sg-current"},
        {"GroupId": "sg-peer"}
      ]
    }
  }
}

test_skip_without_context if {
  skip_reason == "supplementary SG context is required for orphaned security-group reference evaluation" with input as {
    "security_group": {
      "GroupId": "sg-current",
      "IpPermissions": [],
      "IpPermissionsEgress": []
    },
    "sg_context": {}
  }
}
