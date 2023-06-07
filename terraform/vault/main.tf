terraform {
  backend "s3" {
    bucket = "k1-state-store-allfarms-b3wjqi"
    key    = "terraform/vault/terraform.tfstate"

    region  = "ap-southeast-1"
    encrypt = true
  }
  required_providers {
    vault = {
      source = "hashicorp/vault"
    }
  }
}

provider "vault" {
  skip_tls_verify = "true"
}
