# Follow an asynchronous change through to completion.
data "xshield_work_request" "last_change" {
  id = "12345678-1234-1234-1234-123456789012"
}

output "finished" {
  value = data.xshield_work_request.last_change.terminal
}
