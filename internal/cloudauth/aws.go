// Package cloudauth holds the credentials the provider uses to call cloud key services and token services
// directly through their HTTP APIs, each found the way that cloud's own tools find them.
package cloudauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
)

// LoadAWSConfig reads the default AWS credential chain, whose requests go through client. An empty region is found
// in the environment, the shared config files or, failing those, the instance metadata service. A credential_process
// runs as a process that uses its own proxy settings.
func LoadAWSConfig(ctx context.Context, region string, client *http.Client) (aws.Config, error) {
	regionOption := config.WithRegion(region)
	if region == "" {
		regionOption = config.WithEC2IMDSRegion()
	}
	cfg, err := config.LoadDefaultConfig(ctx, regionOption, config.WithHTTPClient(credentialHTTPClient(client)))
	if err != nil {
		return aws.Config{}, fmt.Errorf("loading the AWS credential chain: %w", err)
	}
	return cfg, nil
}

func SignAWSRequest(ctx context.Context, req *http.Request, body []byte, credentials aws.CredentialsProvider, service, region string) error {
	if credentials == nil {
		return fmt.Errorf("no AWS credentials were found in the default credential chain")
	}
	resolved, err := credentials.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("retrieving AWS credentials: %w", err)
	}
	payloadDigest := sha256.Sum256(body)
	return v4.NewSigner().SignHTTP(ctx, resolved, req, hex.EncodeToString(payloadDigest[:]), service, region, time.Now())
}

// AWSServiceEndpoint is the regional endpoint of an AWS service in the partition that owns the region.
func AWSServiceEndpoint(service, region string) string {
	domain := "amazonaws.com"
	if len(region) > 3 && region[:3] == "cn-" {
		domain = "amazonaws.com.cn"
	}
	return "https://" + service + "." + region + "." + domain + "/"
}
