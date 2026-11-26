package sdk_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
)

// The API writes a timestamp it has no value for as "", as it does for an asset never deployed or synchronised.
func TestAssetSummaryReadsAnEmptyTimestampAsUnset(t *testing.T) {
	body := []byte(`{"assetId":"a1","assetName":"vm-1","inboundAssetPolicyUpdatedAt":"","lastFWSynchronized":"",
		"mostRecentNewPath":"","outboundAssetPolicyUpdatedAt":"2026-11-18T22:38:25Z"}`)
	var summary shared.ExtendedAssetSummary
	if err := json.Unmarshal(body, &summary); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for name, got := range map[string]*time.Time{
		"inboundAssetPolicyUpdatedAt": summary.InboundAssetPolicyUpdatedAt,
		"lastFWSynchronized":          summary.LastFWSynchronized,
		"mostRecentNewPath":           summary.MostRecentNewPath,
	} {
		if got != nil {
			t.Errorf("%s: want unset, got %v", name, *got)
		}
	}
	want := time.Date(2026, 11, 18, 22, 38, 25, 0, time.UTC)
	if got := summary.OutboundAssetPolicyUpdatedAt; got == nil || !got.Equal(want) {
		t.Errorf("outboundAssetPolicyUpdatedAt: want %v, got %v", want, got)
	}
}

func TestAssetSummaryStillRefusesAMalformedTimestamp(t *testing.T) {
	var summary shared.ExtendedAssetSummary
	if err := json.Unmarshal([]byte(`{"assetId":"a1","lastFWSynchronized":"yesterday"}`), &summary); err == nil {
		t.Fatal("want an error for a timestamp that is neither empty nor RFC 3339")
	}
}
