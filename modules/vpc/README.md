# VPC Module 🌐

This module provisions the foundational networking infrastructure for the EKS cluster. It sets up a secure, production-grade Virtual Private Cloud (VPC) with public and private subnets across multiple Availability Zones.

## What it Creates 🏗️
1. **VPC (`aws_vpc`)**: The isolated private network. It includes DNS support required for EKS.
2. **Internet Gateway (`aws_internet_gateway`)**: Provides internet access to resources in public subnets.
3. **Public Subnets (`aws_subnet`)**: For internet-facing resources like Application Load Balancers (ALB) and NAT Gateways.
4. **Private Subnets (`aws_subnet`)**: Where the EKS worker nodes run securely. These have no direct internet access.
5. **NAT Gateway (`aws_nat_gateway`)**: Allows resources in private subnets to make outbound requests (e.g., pulling images) without being exposed to inbound internet traffic.
6. **Route Tables (`aws_route_table`)**: Traffic routing rules for public and private subnets.
7. **Network ACLs (`aws_network_acl`)**: A stateless firewall layer at the subnet level for extra security.
8. **VPC Flow Logs (*Optional*)**: Captures network traffic logs for security auditing and troubleshooting (sent to CloudWatch).

## Network Architecture 🗺️
- **Public Subnets** are accessible from the internet via the Internet Gateway.
- **Private Subnets** communicate with the internet only via the NAT Gateway. This is a best practice for securing Kubernetes worker nodes.

## Usage Highlights 💡
- **High Availability**: Subnets are spread across multiple Availability Zones to ensure resilience.
- **NAT Gateway Cost**: You can deploy a single NAT Gateway (cost-saving for Dev) or one per Availability Zone (High Availability for Prod).
- **Subnet Tagging**: Crucial tags (`kubernetes.io/role/elb` and `kubernetes.io/role/internal-elb`) are applied to the subnets so that EKS knows where to correctly provision public and internal load balancers.
