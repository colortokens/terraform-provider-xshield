# Import by id.
terraform import xshield_template.my_template "12345678-1234-1234-1234-123456789012"

# Or by name. The name must be unique; an ambiguous name is reported as an
# error rather than resolved to an arbitrary object.
terraform import xshield_template.my_template "payroll-web"
