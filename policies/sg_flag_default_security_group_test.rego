package compliance_framework.flag_default_security_group

test_violation_default_security_group if {
  count(violation) == 1 with input as {
    "security_group": {
      "GroupName": "default"
    }
  }
}

test_no_violation_non_default_security_group if {
  count(violation) == 0 with input as {
    "security_group": {
      "GroupName": "app-sg"
    }
  }
}

test_skip_non_default_security_group if {
  skip_reason == "security group is not the default security group" with input as {
    "security_group": {
      "GroupName": "app-sg"
    }
  }
}
