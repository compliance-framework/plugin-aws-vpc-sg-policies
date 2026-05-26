package compliance_framework.flag_default_security_group

is_default_security_group if {
  input.security_group.GroupName == "default"
}

violation[{}] if {
  is_default_security_group
}

skip_reason := "security group is not the default security group" if {
  not is_default_security_group
}

title := "Default security group should not be used"
description := "Default security groups are automatically created for each VPC and should not carry workload network access rules"
