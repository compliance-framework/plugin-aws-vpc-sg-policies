package compliance_framework.deny_public_ingress_on_internet_routable_attachment

test_violation_public_ingress_on_internet_routable_attachment if {
  count(violation) == 1 with input as {
    "security_group": {
      "IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "ToPort": 22}],
      "IpPermissionsEgress": []
    },
    "sg_context": {
      "attached_network_interfaces": [{"NetworkInterfaceId": "eni-123"}],
      "route_tables_for_attached_subnets": [{
        "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-123"}]
      }],
      "internet_gateways_for_vpc": [{"InternetGatewayId": "igw-123"}]
    }
  }
}

test_no_violation_without_internet_route if {
  count(violation) == 0 with input as {
    "security_group": {
      "IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "ToPort": 22}],
      "IpPermissionsEgress": []
    },
    "sg_context": {
      "attached_network_interfaces": [{"NetworkInterfaceId": "eni-123"}],
      "route_tables_for_attached_subnets": [{
        "Routes": [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"}]
      }],
      "internet_gateways_for_vpc": [{"InternetGatewayId": "igw-123"}]
    }
  }
}

test_skip_without_context if {
  skip_reason == "supplementary SG context is required for internet-routable attachment evaluation" with input as {
    "security_group": {
      "IpPermissions": [],
      "IpPermissionsEgress": []
    },
    "sg_context": {}
  }
}
