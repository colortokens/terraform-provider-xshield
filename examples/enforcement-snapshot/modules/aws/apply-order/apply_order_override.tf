# Logs each create and destroy of the module's groups, rules and attachments to apply-order.log, in the order the
# apply makes them. A copy of the module with this file beside its own is the module apply-order/tests runs.

resource "aws_security_group" "this" {
  provisioner "local-exec" {
    command = "echo 'create aws_security_group ${each.key}' >> apply-order.log"
  }
  provisioner "local-exec" {
    when    = destroy
    command = "echo 'destroy aws_security_group ${each.key}' >> apply-order.log"
  }
}

resource "aws_vpc_security_group_ingress_rule" "this" {
  provisioner "local-exec" {
    command = "echo 'create aws_vpc_security_group_ingress_rule ${each.key}' >> apply-order.log"
  }
  provisioner "local-exec" {
    when    = destroy
    command = "echo 'destroy aws_vpc_security_group_ingress_rule ${each.key}' >> apply-order.log"
  }
}

resource "aws_network_interface_sg_attachment" "this" {
  provisioner "local-exec" {
    command = "echo 'create aws_network_interface_sg_attachment ${each.key}' >> apply-order.log"
  }
  provisioner "local-exec" {
    when    = destroy
    command = "echo 'destroy aws_network_interface_sg_attachment ${each.key}' >> apply-order.log"
  }
}
