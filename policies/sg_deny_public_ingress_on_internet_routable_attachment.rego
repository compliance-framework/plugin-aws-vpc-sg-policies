package compliance_framework.deny_public_ingress_on_internet_routable_attachment

context_available if {
  input.sg_context.attached_network_interfaces
}

public_source(permission) if {
  cidr := data.public_ipv4_cidrs[_]
  permission.IpRanges[_].CidrIp == cidr
}

public_source(permission) if {
  cidr := data.public_ipv6_cidrs[_]
  permission.Ipv6Ranges[_].CidrIpv6 == cidr
}

attached_to_workload if {
  count(input.sg_context.attached_network_interfaces) > 0
}

internet_gateway_ids[igw_id] if {
  gateway := input.sg_context.internet_gateways_for_vpc[_]
  igw_id := gateway.InternetGatewayId
  igw_id != ""
}

public_ipv4_route_present if {
  route_table := input.sg_context.route_tables_for_attached_subnets[_]
  route := route_table.Routes[_]
  cidr := data.public_ipv4_cidrs[_]
  route.DestinationCidrBlock == cidr
  internet_gateway_ids[route.GatewayId]
}

public_ipv6_route_present if {
  route_table := input.sg_context.route_tables_for_attached_subnets[_]
  route := route_table.Routes[_]
  cidr := data.public_ipv6_cidrs[_]
  route.DestinationIpv6CidrBlock == cidr
  route.EgressOnlyInternetGatewayId != ""
}

public_ipv6_route_present if {
  route_table := input.sg_context.route_tables_for_attached_subnets[_]
  route := route_table.Routes[_]
  cidr := data.public_ipv6_cidrs[_]
  route.DestinationIpv6CidrBlock == cidr
  internet_gateway_ids[route.GatewayId]
}

internet_routable_attachment if {
  attached_to_workload
  public_ipv4_route_present
}

internet_routable_attachment if {
  attached_to_workload
  public_ipv6_route_present
}

violation[{}] if {
  context_available
  permission := input.security_group.IpPermissions[_]
  public_source(permission)
  internet_routable_attachment
}

skip_reason := "supplementary SG context is required for internet-routable attachment evaluation" if {
  not context_available
}

title := "Public ingress on internet-routable attached security groups should be restricted"
description := "Security groups attached to workloads in subnets with internet-routable paths should not allow public ingress unless that exposure is explicitly intended and tightly controlled"
