import "module" "xshield" {
  source = "../../xshield-functions.sentinel"
}

mock "tfplan/v2" {
  module {
    source = "../../testdata/pr/mock-tfplan-v2.sentinel"
  }
}

mock "tfstate/v2" {
  module {
    source = "../../testdata/pr/mock-tfstate-v2.sentinel"
  }
}

test {
  rules = {
    main = false
  }
}
