terraform {
  backend "s3" {
    bucket = "k1-state-store-allfarms-b3wjqi"
    key    = "terraform/aws/terraform.tfstate"

    region  = "ap-southeast-1"
    encrypt = true
  }
}


provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      ClusterName   = "allfarms"
      ProvisionedBy = "kubefirst"
    }
  }
}
module "eks" {
  source = "./eks"

  # aws_account_id     = var.aws_account_id
  # cluster_name       = "allfarms"
  # node_capacity_type = "ON_DEMAND"
  # ami_type           = var.ami_type
  # instance_type      = var.instance_type
}

module "kms" {
  source = "./kms"
}

module "dynamodb" {
  source = "./dynamodb"
}

module "ecr_metaphor" {
  source = "./ecr"

  repository_name = "metaphor"
}

output "vault_unseal_kms_key" {
  // todo https://github.com/terraform-aws-modules/terraform-aws-iam/tree/v4.0.0/examples/iam-assumable-role-with-oidc
  value = module.kms.vault_unseal_kms_key
}
