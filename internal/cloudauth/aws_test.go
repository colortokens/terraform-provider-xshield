package cloudauth

import "testing"

func TestAWSEndpointsFollowThePartition(t *testing.T) {
	cases := map[string]string{
		"us-east-1":     "https://kms.us-east-1.amazonaws.com/",
		"us-gov-west-1": "https://kms.us-gov-west-1.amazonaws.com/",
		"cn-north-1":    "https://kms.cn-north-1.amazonaws.com.cn/",
	}
	for region, want := range cases {
		if got := AWSServiceEndpoint("kms", region); got != want {
			t.Errorf("AWSServiceEndpoint(kms, %s) = %s, want %s", region, got, want)
		}
	}
}
