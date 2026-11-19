# terraform test, offline: where the role is assigned, and that it reaches no further than network writes.

mock_provider "azurerm" {}

variables {
  subscription_id        = "11111111-2222-3333-4444-555555555555"
  pipeline_principal_ids = ["aaaaaaaa-0000-0000-0000-000000000001"]
}

run "the_whole_subscription_by_default" {
  command = plan

  assert {
    condition     = [for a in azurerm_role_assignment.enforcement : a.scope] == ["/subscriptions/11111111-2222-3333-4444-555555555555"]
    error_message = "With no scopes, the role is assigned on the subscription."
  }
}

run "each_listed_resource_group_for_each_identity" {
  command = plan

  variables {
    pipeline_principal_ids = ["aaaaaaaa-0000-0000-0000-000000000001", "aaaaaaaa-0000-0000-0000-000000000002"]
    scopes = [
      "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app",
      "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net",
    ]
  }

  assert {
    condition     = length(azurerm_role_assignment.enforcement) == 4
    error_message = "Each identity is assigned the role on each listed resource group."
  }
}

run "network_actions_only" {
  command = plan

  assert {
    condition     = alltrue([for action in one(azurerm_role_definition.enforcement.permissions).actions : startswith(action, "Microsoft.Network/") || action == "Microsoft.Resources/subscriptions/resources/read"])
    error_message = "The role grants network actions, and the listing of the subscription's resources, and nothing else."
  }
  assert {
    condition     = !anytrue([for action in one(azurerm_role_definition.enforcement.permissions).actions : strcontains(action, "*")])
    error_message = "The role names each action; a wildcard would grant actions added to Azure later."
  }
}

run "an_empty_scope_list_is_refused" {
  command = plan

  variables {
    scopes = []
  }

  expect_failures = [var.scopes]
}

run "no_identity_is_refused" {
  command = plan

  variables {
    pipeline_principal_ids = []
  }

  expect_failures = [var.pipeline_principal_ids]
}
