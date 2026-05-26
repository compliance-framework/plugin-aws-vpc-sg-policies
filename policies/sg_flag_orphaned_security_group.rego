package compliance_framework.flag_orphaned_security_group

context_available if {
  input.sg_context.attached_network_interfaces
}

violation[{}] if {
  context_available
  count(input.sg_context.attached_network_interfaces) == 0
}

skip_reason := "supplementary SG context is required for orphaned security-group evaluation" if {
  not context_available
}

title := "Security group should be attached to an ENI and not orphaned"
description := "Security groups without attached network interfaces are orphaned and retain unused network access rules"
