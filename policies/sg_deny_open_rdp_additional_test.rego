package compliance_framework.deny_open_rdp

test_violation_open_rdp_ipv6 if {
  count(violation) == 1 with input as {
    "security_group": {
      "IpPermissions": [{"Ipv6Ranges": [{"CidrIpv6": "::/0"}], "ToPort": 3389}]
    }
  }
}

test_violation_open_rdp_port_range if {
  count(violation) == 1 with input as {
    "security_group": {
      "IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "FromPort": 3000, "ToPort": 4000}]
    }
  }
}

test_no_violation_open_rdp_private_source if {
  count(violation) == 0 with input as {
    "security_group": {
      "IpPermissions": [{"IpRanges": [{"CidrIp": "10.0.0.0/8"}], "ToPort": 3389}]
    }
  }
}
