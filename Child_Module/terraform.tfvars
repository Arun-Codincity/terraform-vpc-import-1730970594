aws_region = "us-east-1"

vpc_configs = {
  "vpc-0409d972845c508e4": {
    "vpc_id": "vpc-0409d972845c508e4",
    "cidr_block": "10.0.0.0/16",
    "tags": {
      "Name": "arun-test"
    },
    "enable_dns_support": true,
    "enable_dns_hostnames": true
  }
}

subnet_configs = {}

igw_configs = {}

nat_configs = {}

sg_configs = {
  "sg-0528721ca2c264f0f": {
    "name": "default",
    "description": "default VPC security group",
    "vpc_id": "vpc-0409d972845c508e4",
    "ingress": [
      {
        "from_port": 0,
        "to_port": 0,
        "protocol": "-1",
        "cidr_blocks": [
          "0.0.0.0/0"
        ]
      }
    ],
    "egress": [
      {
        "from_port": 0,
        "to_port": 0,
        "protocol": "-1",
        "cidr_blocks": [
          "0.0.0.0/0"
        ]
      }
    ],
    "tags": {}
  }
}

rt_configs = {
  "rtb-0e9b16ece22aebeaf": {
    "vpc_id": "vpc-0409d972845c508e4",
    "routes": [
      {
        "destination_cidr_block": "10.0.0.0/16",
        "gateway_id": "local"
      }
    ],
    "tags": {}
  }
}
