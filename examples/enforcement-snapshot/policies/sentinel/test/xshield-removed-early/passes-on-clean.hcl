import "module" "xshield" {
  source = "../../xshield-functions.sentinel"
}

mock "tfplan/v2" {
  module {
    source = "../../testdata/clean/mock-tfplan-v2.sentinel"
  }
}

mock "tfstate/v2" {
  module {
    source = "../../testdata/clean/mock-tfstate-v2.sentinel"
  }
}

test {
  rules = {
    main = true
  }
}
