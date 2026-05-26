package compliance_framework.deny_orphaned_group_references

context_available if {
  input.sg_context.security_groups_in_vpc
}

known_group_ids[group_id] if {
  group := input.sg_context.security_groups_in_vpc[_]
  group_id := group.GroupId
  group_id != ""
}

violation[{}] if {
  context_available
  permission := input.security_group.IpPermissions[_]
  pair := permission.UserIdGroupPairs[_]
  group_id := pair.GroupId
  group_id != ""
  group_id != input.security_group.GroupId
  not known_group_ids[group_id]
}

violation[{}] if {
  context_available
  permission := input.security_group.IpPermissionsEgress[_]
  pair := permission.UserIdGroupPairs[_]
  group_id := pair.GroupId
  group_id != ""
  group_id != input.security_group.GroupId
  not known_group_ids[group_id]
}

skip_reason := "supplementary SG context is required for orphaned security-group reference evaluation" if {
  not context_available
}

title := "Referenced security groups should exist in the evaluated VPC context"
description := "Security group rules that reference missing peer security groups should be reviewed because they may indicate stale or broken trust relationships"
