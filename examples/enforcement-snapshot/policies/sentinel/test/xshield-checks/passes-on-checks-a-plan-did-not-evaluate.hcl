mock "tfplan/v2" {
  module {
    source = "../../testdata/checks-not-evaluated/mock-tfplan-v2.sentinel"
  }
}

mock "tfstate/v2" {
  module {
    source = "../../testdata/checks-not-evaluated/mock-tfstate-v2.sentinel"
  }
}

test {
  rules = {
    main = true
  }
}
