# Benign Terraform: an ordinary module that must produce zero findings.
# It exercises the same block kinds as the positive sample - a variable, a
# provider, a data source, a resource - with no provisioner, no URL fetch, no
# secret-shaped name and no local_file anywhere.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "instance_count" {
  type    = number
  default = 2
}

provider "aws" {
  region = var.region
}

data "aws_ami" "base" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

resource "aws_instance" "web" {
  count         = var.instance_count
  ami           = data.aws_ami.base.id
  instance_type = "t3.micro"

  tags = {
    Name = "web"
  }
}

output "instance_ids" {
  value = aws_instance.web[*].id
}
