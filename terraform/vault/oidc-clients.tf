module "argo" {
  source = "./modules/oidc-client"

  depends_on = [
    vault_identity_oidc_provider.kubefirst
  ]

  app_name               = "argo"
  identity_group_ids     = [vault_identity_group.admins.id, vault_identity_group.developers.id]
  oidc_provider_key_name = vault_identity_oidc_key.key.name
  redirect_uris = [
    "https://argo.2farm.dev/oauth2/callback",
  ]
  secret_mount_path = "secret"
}

module "argocd" {
  source = "./modules/oidc-client"

  depends_on = [
    vault_identity_oidc_provider.kubefirst
  ]

  app_name               = "argocd"
  identity_group_ids     = [vault_identity_group.admins.id, vault_identity_group.developers.id]
  oidc_provider_key_name = vault_identity_oidc_key.key.name
  redirect_uris = [
    "https://argocd.2farm.dev/auth/callback",
  ]
  secret_mount_path = "secret"
}

module "console" {
  source = "./modules/oidc-client"

  depends_on = [
    vault_identity_oidc_provider.kubefirst
  ]

  app_name               = "console"
  identity_group_ids     = [vault_identity_group.admins.id, vault_identity_group.developers.id]
  oidc_provider_key_name = vault_identity_oidc_key.key.name
  redirect_uris = [
    "https://vouch.2farm.dev/auth",
  ]
  secret_mount_path = "secret"
}

# todo kubectl-oidc
