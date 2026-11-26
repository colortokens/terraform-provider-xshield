# Import an Azure subscription's receipt by subscription ID and region. This adopts the receipt Xshield currently holds,
# which recovers a lost state file without recording a new apply.
terraform import xshield_azure_enforcement_receipt.this "00000000-0000-0000-0000-000000000000/eastus2"
