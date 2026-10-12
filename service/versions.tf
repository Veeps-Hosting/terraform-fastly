terraform {
  # Terragrunt's remote_state fills this in.
  backend "s3" {}

  required_version = ">= 1.12.0"

  required_providers {
    fastly = {
      source  = "fastly/fastly"
      version = "~> 9.8"
    }
  }
}

# No provider block: the provider reads FASTLY_API_KEY from the environment.
# Terragrunt leaves set it per account via extra_arguments env_vars, so the token never lands on disk.
# This module manages BOTH the Fastly CDN delivery service and the Fastly-native Next-Gen WAF
# (workspace model) through this single provider and single credential.
