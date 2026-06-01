package compliance_framework.flag_self_referencing_rules

self_referencing_permission(permission) if {
  permission.UserIdGroupPairs[_].GroupId == input.security_group.GroupId
}

violation[{}] if {
  permission := input.security_group.IpPermissions[_]
  self_referencing_permission(permission)
}

violation[{}] if {
  permission := input.security_group.IpPermissionsEgress[_]
  self_referencing_permission(permission)
}

title := "Self-referencing security group rules should be reviewed"
description := "Security group rules that trust the same security group should be reviewed to confirm they reflect an intentional east-west trust boundary"
