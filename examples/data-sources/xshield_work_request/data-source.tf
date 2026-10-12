# Follow an asynchronous change through to completion.
data "xshield_work_request" "last_change" {
  id = "1f5ed7fa-f6dc-4b57-b963-0f26827662f8"
}

output "finished" {
  value = data.xshield_work_request.last_change.terminal
}
