mock "tfplan/v2" {
  module {
    source = "../../testdata/checks-passed/mock-tfplan-v2.sentinel"
  }
}

mock "tfstate/v2" {
  module {
    source = "../../testdata/checks-passed/mock-tfstate-v2.sentinel"
  }
}

test {
  rules = {
    main = true
  }
}
