package sdk_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/retry"
)

const rawLimit = 64

func rawClient(t *testing.T, declare bool, body string) *sdk.Xshield {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if declare {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		}
		w.WriteHeader(http.StatusOK)
		half := len(body) / 2
		_, _ = w.Write([]byte(body[:half]))
		if f, ok := w.(http.Flusher); ok && !declare {
			f.Flush()
		}
		_, _ = w.Write([]byte(body[half:]))
	}))
	t.Cleanup(srv.Close)
	return sdk.New(sdk.WithServerURL(srv.URL), sdk.WithConfigProvider(signingConfig(t)), sdk.WithClient(srv.Client()))
}

func TestDoRawRefusesABodyOverTheLimitRatherThanCuttingIt(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name          string
		declare       bool
		contentLength int64
	}{{"declared", true, rawLimit + 1}, {"streamed without a length", false, -1}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client := rawClient(t, tc.declare, strings.Repeat("x", rawLimit+1))

			res, err := client.DoRaw(context.Background(), http.MethodGet, client.ServerURL()+"/big", nil, rawLimit, retry.Config{})

			var tooLarge *sdk.ResponseTooLargeError
			if !errors.As(err, &tooLarge) {
				t.Fatalf("got %d bytes and error %v, want a ResponseTooLargeError", len(res.Body), err)
			}
			if tooLarge.Limit != rawLimit || tooLarge.ContentLength != tc.contentLength || res.Body != nil {
				t.Errorf("got %+v and %d bytes, want limit %d, declared %d and no body", tooLarge, len(res.Body), rawLimit, tc.contentLength)
			}
		})
	}
}

func TestDoRawReturnsABodyExactlyAtTheLimit(t *testing.T) {
	t.Parallel()
	client := rawClient(t, false, strings.Repeat("x", rawLimit))

	res, err := client.DoRaw(context.Background(), http.MethodGet, client.ServerURL()+"/edge", nil, rawLimit, retry.Config{})

	if err != nil || len(res.Body) != rawLimit {
		t.Fatalf("got %d bytes and error %v, want %d bytes", len(res.Body), err, rawLimit)
	}
}
