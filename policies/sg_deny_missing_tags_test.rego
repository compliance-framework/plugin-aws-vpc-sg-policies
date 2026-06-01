package compliance_framework.deny_missing_tags

test_violation_missing_required_tags_from_policy_data if {
  count(violation) == 1 with input as {
    "security_group": {
      "Tags": [
        {"Key": "Environment", "Value": "prod"},
        {"Key": "Owner", "Value": "platform"}
      ]
    }
  }
}

test_no_violation_required_tags_from_policy_data_present if {
  count(violation) == 0 with input as {
    "security_group": {
      "Tags": [
        {"Key": "environment", "Value": "prod"},
        {"Key": "OWNER", "Value": "platform"},
        {"Key": "compliance", "Value": "soc2"},
        {"Key": "confidentiality", "Value": "internal"},
        {"Key": "backup", "Value": "false"},
        {"Key": "role", "Value": "web"}
      ]
    }
  }
}

test_violation_missing_configured_required_tag if {
  count(violation) == 1 with input as {
    "security_group": {
      "Tags": [
        {"Key": "owner", "Value": "platform"}
      ]
    }
  } with data.required_tags as ["owner", "cost-center"]
}

test_no_violation_configured_required_tags_present if {
  count(violation) == 0 with input as {
    "security_group": {
      "Tags": [
        {"Key": "OWNER", "Value": "platform"},
        {"Key": "Cost-Center", "Value": "cc-123"}
      ]
    }
  } with data.required_tags as ["owner", "cost-center"]
}
