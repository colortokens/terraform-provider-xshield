# Takes over, without a moment unprotected, the network interfaces and subnets the cloud connector enforced with groups
# of its own while each carried none, when a subscription moves to pipeline delivery. Azure takes an association by
# clearing whatever group its level carries, so the first apply creates Xshield's groups but associates none on those
# levels. Once its receipt reaches Xshield, the cloud connector puts each of Xshield's groups in place of its own in a
# single change, and a later plan imports the association it leaves.
# Add this file to the enforcement workspace before the first apply after the subscription moves to pipeline delivery,
# and delete it once a plan imports nothing.
terraform {
  required_version = ">= 1.7.0"
}

import {
  for_each = module.xshield_enforcement.handover_interface_association_imports
  to       = module.xshield_enforcement.azurerm_network_interface_security_group_association.this[each.key]
  id       = each.value
}

import {
  for_each = module.xshield_enforcement.handover_subnet_association_imports
  to       = module.xshield_enforcement.azurerm_subnet_network_security_group_association.this[each.key]
  id       = each.value
}
