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