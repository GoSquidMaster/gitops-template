# # note: uncomment the below to create a new admin, and be sure to
# # adjust module name admin_one below to your admin's firstname_lastname.
# # create as many admin modules files as you have admin personnel.

module "admin_one" {
  source = "../modules/user"

  acl_policies            = ["admin"]
  email                   = "005@gosquid.io"
  first_name              = "Thai"
  github_username         = "gosquid005"
  last_name               = "Ngo"
  team_id                 = data.github_team.admins.id
  username                = "gosquid005"
  user_disabled           = false
  userpass_accessor       = data.vault_auth_backend.userpass.accessor
}
