# Import a receipt by account, region and the receipt id an Xshield notice names, to destroy one that
# no workspace declares any more, so a revert no longer waits on it. The applying and applied receipts
# share that id, so one import and destroy forgets both.
terraform import xshield_aws_security_group_changes_receipt.orphan "123456789012/us-east-1/0f8fad5b-d9cb-469f-a165-70867728950e"
