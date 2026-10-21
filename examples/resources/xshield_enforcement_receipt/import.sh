# Import by account and region. This adopts the receipt Xshield currently holds,
# which recovers a lost state file without sending a new receipt.
terraform import xshield_enforcement_receipt.this "123456789012/us-east-1"
