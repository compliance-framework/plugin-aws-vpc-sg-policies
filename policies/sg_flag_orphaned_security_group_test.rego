package compliance_framework.flag_orphaned_security_group

test_violation_orphaned_security_group if {
  count(violation) == 1 with input as {
    "security_group": {
      "GroupId": "sg-orphaned"
    },
    "sg_context": {
      "attached_network_interfaces": []
    }
  }
}

test_no_violation_attached_security_group if {
  count(violation) == 0 with input as {
    "security_group": {
      "GroupId": "sg-attached"
    },
    "sg_context": {
      "attached_network_interfaces": [
        {"NetworkInterfaceId": "eni-123"}
      ]
    }
  }
}

test_skip_without_context if {
  skip_reason == "supplementary SG context is required for orphaned security-group evaluation" with input as {
    "security_group": {
      "GroupId": "sg-unknown"
    },
    "sg_context": {}
  }
}
