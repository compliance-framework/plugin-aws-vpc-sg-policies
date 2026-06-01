package compliance_framework.deny_missing_tags

required_tags[tag] if {
  tag := data.required_tags[_]
}

missing_tags[tag] if {
  required_tags[tag]
  not tag_exists(input.security_group.Tags, tag)
}

violation[{}] if {
  count(missing_tags) > 0
}

tag_exists(tags, tag_name) if {
  some tag in tags
  lower(tag.Key) == lower(tag_name)
}

title := "Security groups should set required tags"
description := "Security group tags should contain all required tag keys defined by policy"
remarks := "Policy ensures required tags are set on security groups using data.required_tags from policy data."
