provider "aws" {
  region = var.aws_region
}

resource "aws_vpc" "imported_vpc" {
  for_each = var.vpc_configs

  cidr_block           = each.value.cidr_block
  enable_dns_support   = each.value.enable_dns_support
  enable_dns_hostnames = each.value.enable_dns_hostnames
  tags                 = each.value.tags
}

resource "aws_subnet" "imported_subnet" {
  for_each = var.subnet_configs

  vpc_id                  = each.value.vpc_id
  cidr_block              = each.value.cidr_block
  availability_zone       = each.value.availability_zone
  map_public_ip_on_launch = each.value.map_public_ip
  tags                    = each.value.tags
}

# Internet Gateway Resource
resource "aws_internet_gateway" "imported_igw" {
  for_each = var.igw_configs

  vpc_id = each.value.vpc_id
  tags   = each.value.tags
}

# NAT Gateway Resource
resource "aws_nat_gateway" "imported_nat" {
  for_each = var.nat_configs

  subnet_id = each.value.subnet_id
  tags      = each.value.tags
}

# Security Group Resource
resource "aws_security_group" "imported_sg" {
  for_each = var.sg_configs

  name        = each.value.name
  description = each.value.description
  vpc_id      = each.value.vpc_id
  tags        = each.value.tags

  dynamic "ingress" {
    for_each = each.value.ingress
    content {
      from_port   = ingress.value.from_port
      to_port     = ingress.value.to_port
      protocol    = ingress.value.protocol
      cidr_blocks = ingress.value.cidr_blocks
    }
  }

  dynamic "egress" {
    for_each = each.value.egress
    content {
      from_port   = egress.value.from_port
      to_port     = egress.value.to_port
      protocol    = egress.value.protocol
      cidr_blocks = egress.value.cidr_blocks
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Route Table Resource
resource "aws_route_table" "imported_rt" {
  for_each = var.rt_configs

  vpc_id = each.value.vpc_id
  tags   = each.value.tags

  dynamic "route" {
    for_each = each.value.routes
    content {
      cidr_block = route.value.destination_cidr_block
      gateway_id = route.value.gateway_id
    }
  }
}