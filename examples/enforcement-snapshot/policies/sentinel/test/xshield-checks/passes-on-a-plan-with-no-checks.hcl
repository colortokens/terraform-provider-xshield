mock "tfplan/v2" {
  module {
    source = "../../testdata/no-checks/mock-tfplan-v2.sentinel"
  }
}

mock "tfstate/v2" {
  module {
    source = "../../testdata/no-checks/mock-tfstate-v2.sentinel"
  }
}

test {
  rules = {
    main = true
  }
}
