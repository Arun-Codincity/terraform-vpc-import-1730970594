variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "vpc_configs" {
  description = "VPC configurations"
  type = map(object({
    cidr_block           = string
    enable_dns_support   = bool
    enable_dns_hostnames = bool
    tags                 = map(string)
  }))
}

variable "subnet_configs" {
  description = "Subnet configurations"
  type = map(object({
    vpc_id            = string
    cidr_block        = string
    availability_zone = string
    map_public_ip     = bool
    tags              = map(string)
  }))
}

variable "igw_configs" {
  description = "Internet Gateway configurations"
  type = map(object({
    vpc_id = string
    tags   = map(string)
  }))
}

variable "nat_configs" {
  description = "NAT Gateway configurations"
  type = map(object({
    subnet_id = string
    tags      = map(string)
  }))
}

variable "sg_configs" {
  description = "Security Group configurations"
  type = map(object({
    name        = string
    description = string
    vpc_id      = string
    ingress     = list(object({
      from_port   = number
      to_port     = number
      protocol    = string
      cidr_blocks = list(string)
    }))
    egress      = list(object({
      from_port   = number
      to_port     = number
      protocol    = string
      cidr_blocks = list(string)
    }))
    tags        = map(string)
  }))
}

variable "rt_configs" {
  description = "Route Table configurations"
  type = map(object({
    vpc_id = string
    routes = list(object({
      destination_cidr_block = string
      gateway_id             = string
    }))
    tags = map(string)
  }))
}