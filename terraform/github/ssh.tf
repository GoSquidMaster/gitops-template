resource "github_user_ssh_key" "kbot" {
  title = "kbot-allfarms"
  key   = var.kbot_ssh_public_key
}

variable "kbot_ssh_public_key" {
  type    = string
  default = ""
}
