package compliance_framework.deny_open_ssh

test_violation_open_ssh_ipv6 if {
  count(violation) == 1 with input as {
    "security_group": {
      "IpPermissions": [{"Ipv6Ranges": [{"CidrIpv6": "::/0"}], "ToPort": 22}]
    }
  }
}

test_violation_open_ssh_port_range if {
  count(violation) == 1 with input as {
    "security_group": {
      "IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "FromPort": 20, "ToPort": 30}]
    }
  }
}

test_no_violation_open_ssh_private_source if {
  count(violation) == 0 with input as {
    "security_group": {
      "IpPermissions": [{"IpRanges": [{"CidrIp": "10.0.0.0/8"}], "ToPort": 22}]
    }
  }
}
