mock "tfplan/v2" {
  module {
    source = "../../testdata/check-failed/mock-tfplan-v2.sentinel"
  }
}

mock "tfstate/v2" {
  module {
    source = "../../testdata/check-failed/mock-tfstate-v2.sentinel"
  }
}

test {
  rules = {
    main = false
  }
}
