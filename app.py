# app.py (backend)
from flask import Flask, request, jsonify, send_file, render_template
from flask_cors import CORS
import subprocess
import os
import json
import boto3
from typing import Dict, List, Tuple
import sys
import time
from io import BytesIO
import pandas as pd
from flask_socketio import SocketIO
import requests  # For GitHub API interactions

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")  # Initialize Socket.IO


@app.route("/")
def index():
    return render_template("index.html")


def fetch_vpc_resources(vpc_ids: List[str], region: str, aws_access_key_id: str, aws_secret_access_key: str) -> Dict[str, Dict]:
    """Fetch all VPC and associated resource details."""
    session = boto3.Session(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region
    )
    ec2_client = session.client('ec2')
    resource_details = {}

    # If vpc_ids is None or empty, fetch all VPCs
    if not vpc_ids:
        vpc_response = ec2_client.describe_vpcs()
        vpc_ids = [vpc['VpcId'] for vpc in vpc_response['Vpcs']]

    for vpc_id in vpc_ids:
        resource_details[vpc_id] = {
            'vpc': {},
            'subnets': [],
            'internet_gateways': [],
            'nat_gateways': [],
            'security_groups': [],
            'route_tables': []
        }

        # Fetch VPC details with error handling
        try:
            vpc_response = ec2_client.describe_vpcs(VpcIds=[vpc_id])
            vpc = vpc_response['Vpcs'][0]
            vpc_details = {
                'vpc_id': vpc_id,
                'cidr_block': vpc['CidrBlock'],
                'tags': {tag['Key']: tag['Value'] for tag in vpc.get('Tags', [])},
                'enable_dns_support': True,
                'enable_dns_hostnames': True
            }
            resource_details[vpc_id]['vpc'] = vpc_details
        except Exception as e:
            print(f"Error fetching VPC details: {str(e)}")
            continue

        try:
            # Fetch Subnets
            paginator = ec2_client.get_paginator('describe_subnets')
            for page in paginator.paginate(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]):
                for subnet in page['Subnets']:
                    subnet_details = {
                        'id': subnet['SubnetId'],
                        'cidr_block': subnet['CidrBlock'],
                        'availability_zone': subnet['AvailabilityZone'],
                        'map_public_ip': subnet.get('MapPublicIpOnLaunch', False),
                        'tags': {tag['Key']: tag['Value'] for tag in subnet.get('Tags', [])}
                    }
                    resource_details[vpc_id]['subnets'].append(subnet_details)

            # Fetch Internet Gateways
            igw_response = ec2_client.describe_internet_gateways(
                Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}]
            )
            for igw in igw_response['InternetGateways']:
                igw_details = {
                    'id': igw['InternetGatewayId'],
                    'tags': {tag['Key']: tag['Value'] for tag in igw.get('Tags', [])},
                    'vpc_id': vpc_id
                }
                resource_details[vpc_id]['internet_gateways'].append(igw_details)

            # Fetch NAT Gateways
            paginator = ec2_client.get_paginator('describe_nat_gateways')
            for page in paginator.paginate(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]):
                for nat in page['NatGateways']:
                    if nat['State'] != 'deleted':
                        nat_details = {
                            'id': nat['NatGatewayId'],
                            'subnet_id': nat['SubnetId'],
                            'allocation_id': next((addr.get('AllocationId') for addr in nat['NatGatewayAddresses'] if 'AllocationId' in addr), None),
                            'tags': {tag['Key']: tag['Value'] for tag in nat.get('Tags', [])},
                            'vpc_id': vpc_id
                        }
                        resource_details[vpc_id]['nat_gateways'].append(nat_details)

            # Fetch Security Groups
            paginator = ec2_client.get_paginator('describe_security_groups')
            for page in paginator.paginate(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]):
                for sg in page['SecurityGroups']:
                    sg_details = {
                        'id': sg['GroupId'],
                        'name': sg['GroupName'],
                        'description': sg['Description'],
                        'tags': {tag['Key']: tag['Value'] for tag in sg.get('Tags', [])},
                        'ingress_rules': sg.get('IpPermissions', []),
                        'egress_rules': sg.get('IpPermissionsEgress', []),
                        'vpc_id': vpc_id
                    }
                    resource_details[vpc_id]['security_groups'].append(sg_details)

            # Fetch Route Tables
            paginator = ec2_client.get_paginator('describe_route_tables')
            for page in paginator.paginate(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]):
                for rt in page['RouteTables']:
                    rt_details = {
                        'id': rt['RouteTableId'],
                        'tags': {tag['Key']: tag['Value'] for tag in rt.get('Tags', [])},
                        'routes': [
                            {
                                'destination': route.get('DestinationCidrBlock', route.get('DestinationIpv6CidrBlock', '')),
                                'target': next((v for k, v in route.items() if k.endswith('Id') and v), None),
                                'state': route.get('State', 'active')
                            }
                            for route in rt.get('Routes', [])
                        ],
                        'associations': [
                            {
                                'id': assoc['RouteTableAssociationId'],
                                'subnet_id': assoc.get('SubnetId'),
                                'main': assoc.get('Main', False)
                            }
                            for assoc in rt.get('Associations', [])
                        ],
                        'vpc_id': vpc_id
                    }
                    resource_details[vpc_id]['route_tables'].append(rt_details)

        except Exception as e:
            print(f"Error fetching resources: {str(e)}")

    return resource_details


def create_terraform_files(parent_module: str, child_module: str):
    """Create minimal Terraform files focusing on VPC and Subnet resources."""
    # Parent Module Files
    parent_variables_tf = """
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
""".strip()

    parent_main_tf = """
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
""".strip()

    # Child Module Files
    child_main_tf = """
module "vpc_resources" {
  source = "../Parent_Module"

  aws_region     = var.aws_region
  vpc_configs    = var.vpc_configs
  subnet_configs = var.subnet_configs
  igw_configs    = var.igw_configs
  nat_configs    = var.nat_configs
  sg_configs     = var.sg_configs
  rt_configs     = var.rt_configs
}
""".strip()

    child_variables_tf = """
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
""".strip()

    # Write files
    files_to_create = [
        (os.path.join(parent_module, "variables.tf"), parent_variables_tf),
        (os.path.join(parent_module, "main.tf"), parent_main_tf),
        (os.path.join(child_module, "variables.tf"), child_variables_tf),
        (os.path.join(child_module, "main.tf"), child_main_tf),
    ]

    for file_path, content in files_to_create:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w") as f:
            f.write(content)


def create_tfvars(child_module: str, resource_details: Dict, region: str):
    """Create or update terraform.tfvars with new VPC configurations while preserving existing ones."""
    tfvars_path = os.path.join(child_module, "terraform.tfvars")

    # Process new configurations
    vpc_configs = {}
    subnet_configs = {}
    igw_configs = {}
    nat_configs = {}
    sg_configs = {}
    rt_configs = {}

    for vpc_id, resources in resource_details.items():
        # VPC Configuration
        vpc_configs[vpc_id] = resources['vpc']

        # Subnet Configurations
        for subnet in resources['subnets']:
            subnet_id = subnet['id']
            subnet_configs[subnet_id] = {
                'vpc_id': vpc_id,
                'cidr_block': subnet['cidr_block'],
                'availability_zone': subnet['availability_zone'],
                'map_public_ip': subnet['map_public_ip'],
                'tags': subnet['tags']
            }

        # IGW Configurations
        for igw in resources['internet_gateways']:
            igw_id = igw['id']
            igw_configs[igw_id] = {
                'vpc_id': vpc_id,
                'tags': igw['tags']
            }

        # NAT Configurations
        for nat in resources['nat_gateways']:
            nat_id = nat['id']
            nat_configs[nat_id] = {
                'subnet_id': nat['subnet_id'],
                'tags': nat['tags']
            }

        # Security Group Configurations
        for sg in resources['security_groups']:
            sg_id = sg['id']

            # Process ingress rules with safe defaults
            processed_ingress = []
            try:
                raw_ingress = sg.get('ingress_rules', [])
                for rule in raw_ingress:
                    processed_rule = {
                        'from_port': int(rule.get('FromPort', 0)) if rule.get('FromPort') is not None else 0,
                        'to_port': int(rule.get('ToPort', 0)) if rule.get('ToPort') is not None else 0,
                        'protocol': rule.get('IpProtocol', '-1'),
                        'cidr_blocks': [ip_range.get('CidrIp', '0.0.0.0/0') for ip_range in rule.get('IpRanges', [])]
                    }

                    if not processed_rule['cidr_blocks']:
                        processed_rule['cidr_blocks'] = ['0.0.0.0/0']

                    processed_ingress.append(processed_rule)
            except Exception as e:
                print(f"Warning: Error processing ingress rules for SG {sg_id}: {str(e)}")

            # Process egress rules with safe defaults
            processed_egress = []
            try:
                raw_egress = sg.get('egress_rules', [])
                if not raw_egress:
                    processed_egress = [{
                        'from_port': 0,
                        'to_port': 0,
                        'protocol': '-1',
                        'cidr_blocks': ['0.0.0.0/0']
                    }]
                else:
                    for rule in raw_egress:
                        processed_rule = {
                            'from_port': int(rule.get('FromPort', 0)) if rule.get('FromPort') is not None else 0,
                            'to_port': int(rule.get('ToPort', 0)) if rule.get('ToPort') is not None else 0,
                            'protocol': rule.get('IpProtocol', '-1'),
                            'cidr_blocks': [ip_range.get('CidrIp', '0.0.0.0/0') for ip_range in rule.get('IpRanges', [])]
                        }

                        if not processed_rule['cidr_blocks']:
                            processed_rule['cidr_blocks'] = ['0.0.0.0/0']

                        processed_egress.append(processed_rule)
            except Exception as e:
                print(f"Warning: Error processing egress rules for SG {sg_id}: {str(e)}")

            sg_configs[sg_id] = {
                'name': sg.get('name', f'sg-{sg_id}'),
                'description': sg.get('description', 'Managed by Terraform'),
                'vpc_id': vpc_id,
                'ingress': processed_ingress,
                'egress': processed_egress,
                'tags': sg.get('tags', {})
            }

        # Route Table Configurations
        for rt in resources['route_tables']:
            rt_id = rt['id']
            processed_routes = []

            for route in rt['routes']:
                if route['destination'] and route['target']:
                    processed_routes.append({
                        'destination_cidr_block': route['destination'],
                        'gateway_id': route['target']
                    })

            rt_configs[rt_id] = {
                'vpc_id': vpc_id,
                'routes': processed_routes,
                'tags': rt['tags']
            }

    # Build tfvars content
    tfvars_content = f"""aws_region = "{region}"

vpc_configs = {json.dumps(vpc_configs, indent=2)}

subnet_configs = {json.dumps(subnet_configs, indent=2)}

igw_configs = {json.dumps(igw_configs, indent=2)}

nat_configs = {json.dumps(nat_configs, indent=2)}

sg_configs = {json.dumps(sg_configs, indent=2)}

rt_configs = {json.dumps(rt_configs, indent=2)}
"""

    # Write to tfvars file
    with open(tfvars_path, "w") as f:
        f.write(tfvars_content)


def run_terraform_command(command: List[str], cwd: str, aws_access_key_id: str, aws_secret_access_key: str, sid: str, timeout: int = 300) -> bool:
    """Run Terraform command with timeout and better error handling."""
    try:
        env = os.environ.copy()
        env['AWS_ACCESS_KEY_ID'] = aws_access_key_id
        env['AWS_SECRET_ACCESS_KEY'] = aws_secret_access_key

        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1
        )

        message = f"\nExecuting: {' '.join(command)}"
        print(message)
        socketio.emit('log', message, to=sid)

        start_time = time.time()
        while True:
            if process.poll() is not None:
                break

            if time.time() - start_time > timeout:
                process.terminate()
                timeout_message = f"Command timed out after {timeout} seconds"
                print(timeout_message)
                socketio.emit('log', timeout_message, to=sid)
                return False

            output = process.stdout.readline()
            if output:
                print(output.strip())
                socketio.emit('log', output.strip(), to=sid)
            error = process.stderr.readline()
            if error:
                error_message = f"ERROR: {error.strip()}"
                print(error_message, file=sys.stderr)
                socketio.emit('log', error_message, to=sid)

            time.sleep(0.1)

        return_code = process.poll()
        return return_code == 0

    except Exception as e:
        error_message = f"Error executing Terraform command: {str(e)}"
        print(error_message)
        socketio.emit('log', error_message, to=sid)
        return False


def import_resources(child_module: str, resource_details: Dict, aws_access_key_id: str, aws_secret_access_key: str, sid: str):
    """Import VPC and associated resources with improved error handling."""
    results = {"success": [], "failed": []}
    log_output = []  # List to accumulate log messages

    try:
        os.chdir(child_module)

        # Initialize Terraform with backend configuration
        if not run_terraform_command(['terraform', 'init'], child_module, aws_access_key_id, aws_secret_access_key, sid):
            raise Exception("Terraform initialization failed")

        # Import VPCs first
        for vpc_id in resource_details.keys():
            message = f"\nImporting VPC {vpc_id}..."
            print(message)
            socketio.emit('log', message, to=sid)
            success = run_terraform_command([
                'terraform', 'import',
                f'module.vpc_resources.aws_vpc.imported_vpc["{vpc_id}"]',
                vpc_id
            ], child_module, aws_access_key_id, aws_secret_access_key, sid)

            if success:
                log_output.append(f"Successfully imported VPC {vpc_id}")
                socketio.emit('log', f"Successfully imported VPC {vpc_id}", to=sid)
                results["success"].append(vpc_id)
            else:
                log_output.append(f"Failed to import VPC {vpc_id}")
                socketio.emit('log', f"Failed to import VPC {vpc_id}", to=sid)
                results["failed"].append(vpc_id)
                continue

            # Import associated subnets
            for subnet in resource_details[vpc_id]['subnets']:
                subnet_id = subnet['id']
                message = f"Importing Subnet {subnet_id}..."
                print(message)
                socketio.emit('log', message, to=sid)
                run_terraform_command([
                    'terraform', 'import',
                    f'module.vpc_resources.aws_subnet.imported_subnet["{subnet_id}"]',
                    subnet_id
                ], child_module, aws_access_key_id, aws_secret_access_key, sid)

            # Import Internet Gateways
            for igw in resource_details[vpc_id]['internet_gateways']:
                igw_id = igw['id']
                message = f"Importing Internet Gateway {igw_id}..."
                print(message)
                socketio.emit('log', message, to=sid)
                run_terraform_command([
                    'terraform', 'import',
                    f'module.vpc_resources.aws_internet_gateway.imported_igw["{igw_id}"]',
                    igw_id
                ], child_module, aws_access_key_id, aws_secret_access_key, sid)

            # Import NAT Gateways
            for nat in resource_details[vpc_id]['nat_gateways']:
                nat_id = nat['id']
                message = f"Importing NAT Gateway {nat_id}..."
                print(message)
                socketio.emit('log', message, to=sid)
                run_terraform_command([
                    'terraform', 'import',
                    f'module.vpc_resources.aws_nat_gateway.imported_nat["{nat_id}"]',
                    nat_id
                ], child_module, aws_access_key_id, aws_secret_access_key, sid)

            # Import Security Groups
            for sg in resource_details[vpc_id]['security_groups']:
                sg_id = sg['id']
                message = f"Importing Security Group {sg_id}..."
                print(message)
                socketio.emit('log', message, to=sid)
                run_terraform_command([
                    'terraform', 'import',
                    f'module.vpc_resources.aws_security_group.imported_sg["{sg_id}"]',
                    sg_id
                ], child_module, aws_access_key_id, aws_secret_access_key, sid)

            # Import Route Tables
            for rt in resource_details[vpc_id]['route_tables']:
                rt_id = rt['id']
                message = f"Importing Route Table {rt_id}..."
                print(message)
                socketio.emit('log', message, to=sid)
                run_terraform_command([
                    'terraform', 'import',
                    f'module.vpc_resources.aws_route_table.imported_rt["{rt_id}"]',
                    rt_id
                ], child_module, aws_access_key_id, aws_secret_access_key, sid)

    except Exception as e:
        error_message = f"Error during import: {str(e)}"
        print(error_message)
        socketio.emit('log', error_message, to=sid)
    finally:
        os.chdir(os.path.dirname(child_module))

    # Return both import_log and results
    import_log = "\n".join(log_output)
    return import_log, results


def generate_excel_file(resource_details):
    """Generate an Excel file from resource details."""
    output = BytesIO()
    writer = pd.ExcelWriter(output, engine='xlsxwriter')

    # For each VPC, write details to separate sheets
    for vpc_id, resources in resource_details.items():
        # VPC details
        vpc_df = pd.DataFrame([resources['vpc']])
        vpc_df.to_excel(writer, sheet_name=f'{vpc_id}_VPC', index=False)

        # Subnets
        subnets_df = pd.DataFrame(resources['subnets'])
        subnets_df.to_excel(writer, sheet_name=f'{vpc_id}_Subnets', index=False)

        # Internet Gateways
        igw_df = pd.DataFrame(resources['internet_gateways'])
        igw_df.to_excel(writer, sheet_name=f'{vpc_id}_IGWs', index=False)

        # NAT Gateways
        nat_df = pd.DataFrame(resources['nat_gateways'])
        nat_df.to_excel(writer, sheet_name=f'{vpc_id}_NATs', index=False)

        # Security Groups
        sg_df = pd.DataFrame(resources['security_groups'])
        sg_df.to_excel(writer, sheet_name=f'{vpc_id}_SGs', index=False)

        # Route Tables
        rt_df = pd.DataFrame(resources['route_tables'])
        rt_df.to_excel(writer, sheet_name=f'{vpc_id}_RTs', index=False)

    writer.close()
    output.seek(0)
    return output


def create_github_repository(repo_name: str, description: str, github_token: str) -> Tuple[str, str]:
    """Create a new GitHub repository and return the clone URL and owner login."""
    url = 'https://api.github.com/user/repos'
    headers = {
        'Authorization': f'token {github_token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    data = {
        'name': repo_name,
        'description': description,
        'private': False,  # Set to True if you want a private repository
    }
    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 201:
        repo_info = response.json()
        clone_url = repo_info['clone_url']
        owner_login = repo_info['owner']['login']
        return clone_url, owner_login
    else:
        error_message = response.json().get('message', 'Unknown error')
        raise Exception(f"Failed to create GitHub repository: {error_message}")


def create_gitignore_file(base_path: str):
    """Create a .gitignore file to exclude unnecessary files from the Git repository."""
    gitignore_content = """
# Exclude Terraform directories and files
.terraform/
*.tfstate
*.tfstate.backup
terraform.tfvars
.terraform.lock.hcl

# Exclude any log files
*.log

# Exclude Python compiled files
__pycache__/
*.pyc

# Exclude system files
.DS_Store
Thumbs.db
""".strip()

    gitignore_path = os.path.join(base_path, ".gitignore")
    with open(gitignore_path, "w") as f:
        f.write(gitignore_content)


@app.route('/validate-credentials', methods=['POST'])
def validate_credentials():
    data = request.json
    aws_access_key_id = data.get('aws_access_key_id')
    aws_secret_access_key = data.get('aws_secret_access_key')

    # Validate the credentials
    try:
        session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
        )
        sts_client = session.client('sts')
        sts_client.get_caller_identity()
        return jsonify({'message': 'Credentials are valid'}), 200
    except Exception as e:
        print(f"Error validating credentials: {str(e)}")
        return jsonify({'message': 'Invalid AWS credentials', 'error': str(e)}), 401


@app.route('/run-script', methods=['POST'])
def run_script():
    data = request.json
    region = data.get('region')
    aws_access_key_id = data.get('aws_access_key_id')
    aws_secret_access_key = data.get('aws_secret_access_key')
    sid = data.get('sid')  # Get the Socket.IO session ID from the request
    import_all_vpcs = data.get('importAllVpcs', False)

    try:
        base_path = os.path.abspath(os.path.dirname(__file__))
        parent_module = os.path.join(base_path, "Parent_Module")
        child_module = os.path.join(base_path, "Child_Module")

        # Create Terraform files only if they don't exist
        if not os.path.exists(parent_module) or not os.path.exists(child_module):
            message = "Creating Terraform files..."
            print(message)
            socketio.emit('log', message, to=sid)
            create_terraform_files(parent_module, child_module)

        # Fetch VPC details
        message = "Fetching VPC details..."
        print(message)
        socketio.emit('log', message, to=sid)

        if import_all_vpcs:
            # Fetch all VPC IDs in the region
            session = boto3.Session(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region_name=region
            )
            ec2_client = session.client('ec2')
            response = ec2_client.describe_vpcs()
            vpc_ids = [vpc['VpcId'] for vpc in response['Vpcs']]
            if not vpc_ids:
                error_message = "No VPCs found in the selected region."
                print(error_message)
                socketio.emit('log', error_message, to=sid)
                return jsonify({'message': error_message}), 404
        else:
            vpc_ids_input = data.get('vpcIds')
            vpc_ids = vpc_ids_input

        resource_details = fetch_vpc_resources(vpc_ids, region, aws_access_key_id, aws_secret_access_key)

        # Create/Update tfvars
        message = "Updating terraform.tfvars..."
        print(message)
        socketio.emit('log', message, to=sid)
        create_tfvars(child_module, resource_details, region)

        # Import resources and get import log and results
        message = "Importing resources..."
        print(message)
        socketio.emit('log', message, to=sid)
        import_log, results = import_resources(child_module, resource_details, aws_access_key_id, aws_secret_access_key, sid)

        # Create a new GitHub repository and push the generated Terraform modules
        try:
            # Get GitHub token from environment variable
            github_token = os.environ.get('GITHUB_TOKEN')
            if not github_token:
                error_message = "GitHub token not found. Please set the GITHUB_TOKEN environment variable."
                print(error_message)
                socketio.emit('log', error_message, to=sid)
                return jsonify({'message': error_message}), 500

            repo_name = f"terraform-vpc-import-{int(time.time())}"
            description = "Terraform modules generated by Terra-Auto"
            message = f"Creating GitHub repository {repo_name}..."
            print(message)
            socketio.emit('log', message, to=sid)

            clone_url, owner_login = create_github_repository(repo_name, description, github_token)

            # Create .gitignore file
            create_gitignore_file(base_path)

            # Remove existing .git directory if it exists
            git_dir = os.path.join(base_path, '.git')
            if os.path.exists(git_dir):
                if os.name == 'nt':
                    subprocess.run(['rmdir', '/S', '/Q', git_dir], shell=True)
                else:
                    subprocess.run(['rm', '-rf', git_dir], cwd=base_path)

            # Initialize Git repository in the base path
            message = f"Initializing Git repository in {base_path}..."
            print(message)
            socketio.emit('log', message, to=sid)

            # Initialize git repository
            subprocess.run(['git', 'init'], cwd=base_path)

            # Add .gitignore file to Git
            subprocess.run(['git', 'add', '.gitignore'], cwd=base_path)

            # Configure user name and email
            subprocess.run(['git', 'config', 'user.name', 'Terra-Auto'], cwd=base_path)
            subprocess.run(['git', 'config', 'user.email', 'terra-auto@example.com'], cwd=base_path)

            # Add other files
            subprocess.run(['git', 'add', '.'], cwd=base_path)

            # Commit changes
            subprocess.run(['git', 'commit', '-m', 'Initial commit of Terraform modules'], cwd=base_path)

            # Add remote
            subprocess.run(['git', 'remote', 'add', 'origin', clone_url], cwd=base_path)

            # Push to remote using the token in the URL
            message = "Pushing to GitHub repository..."
            print(message)
            socketio.emit('log', message, to=sid)

            # Replace 'https://' with 'https://<token>@' in clone_url
            push_url = clone_url.replace('https://', f'https://{github_token}@')

            # Use subprocess to run 'git push -u origin master'
            result = subprocess.run(['git', 'push', '-u', push_url, 'master'], cwd=base_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if result.returncode != 0:
                error_message = f"Error pushing to GitHub: {result.stderr}"
                print(error_message)
                socketio.emit('log', error_message, to=sid)
                return jsonify({'message': error_message}), 500

            repo_url = f'https://github.com/{owner_login}/{repo_name}'

            message = f"Repository URL: {repo_url}"
            print(message)
            socketio.emit('log', message, to=sid)

        except Exception as e:
            error_message = f"Error pushing to GitHub: {str(e)}"
            print(error_message)
            socketio.emit('log', error_message, to=sid)
            return jsonify({'message': error_message}), 500

        # Return the import log and results in the response, along with the repo URL
        return jsonify({
            'message': 'Script executed successfully',
            'import_log': import_log,
            'results': results,
            'repo_url': repo_url
        }), 200

    except Exception as e:
        error_message = f"Error running script: {str(e)}"
        print(error_message)
        socketio.emit('log', error_message, to=sid)
        return jsonify({'message': str(e)}), 500


@app.route('/download-excel', methods=['GET'])
def download_excel():
    data = request.args
    vpc_ids_input = data.get('vpcIds')
    region = data.get('region')
    aws_access_key_id = data.get('aws_access_key_id')
    aws_secret_access_key = data.get('aws_secret_access_key')
    import_all_vpcs = data.get('importAllVpcs', 'false').lower() == 'true'

    try:
        if import_all_vpcs:
            # Fetch all VPC IDs in the region
            session = boto3.Session(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region_name=region
            )
            ec2_client = session.client('ec2')
            response = ec2_client.describe_vpcs()
            vpc_ids = [vpc['VpcId'] for vpc in response['Vpcs']]
            if not vpc_ids:
                return jsonify({'message': 'No VPCs found in the selected region.'}), 404
        else:
            vpc_ids = vpc_ids_input.split(',')

        resource_details = fetch_vpc_resources(vpc_ids, region, aws_access_key_id, aws_secret_access_key)

        # Generate Excel file
        excel_file = generate_excel_file(resource_details)

        # Send the Excel file as attachment
        return send_file(
            excel_file,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name='vpc_details.xlsx'  # For Flask >= 2.0
        )

    except Exception as e:
        print(f"Error generating Excel file: {str(e)}")
        return jsonify({'message': f'Error generating Excel file: {str(e)}'}), 500


if __name__ == '__main__':
    socketio.run(app, debug=True)  # Use socketio.run instead of app.run
