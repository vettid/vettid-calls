package awsx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/vettid/vettid-calls/internal/secretsrc"
	"github.com/vettid/vettid-calls/internal/turnsstatus"
)

// An SSM endpoint answering every call with status and body.
func ssmStub(t *testing.T, status int, body string, calls *int) *ssm.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return ssm.New(ssm.Options{Region: "us-east-1", BaseEndpoint: aws.String(srv.URL), RetryMaxAttempts: 1,
		Credentials: credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "test", "")})
}

func TestParameterGet(t *testing.T) {
	var calls int
	p := &Parameter{Client: ssmStub(t, 200, `{"Parameter":{"Name":"/x","Type":"String","Value":"{\"verified_at\":1,\"not_after\":2}"}}`, &calls), Name: "/x"}
	b, err := p.Get(context.Background())
	if err != nil || string(b) != `{"verified_at":1,"not_after":2}` {
		t.Fatalf("%q %v", b, err)
	}
	p.Client = ssmStub(t, 400, `{"__type":"ParameterNotFound","message":"nope"}`, &calls)
	if _, err := p.Get(context.Background()); !errors.Is(err, turnsstatus.ErrNotFound) {
		t.Fatalf("not found: %v", err)
	}
	calls = 0
	p.Client = ssmStub(t, 500, `{"__type":"InternalServerError","message":"x"}`, &calls)
	_, err = p.Get(context.Background())
	if err == nil || errors.Is(err, turnsstatus.ErrNotFound) {
		t.Fatalf("a failure read as not found: %v", err)
	}
	if calls != 1 {
		t.Fatalf("%d attempts with RetryMaxAttempts 1", calls)
	}
}

// NewParameter makes one attempt per read.
func TestNewParameterNoRetries(t *testing.T) {
	p := NewParameter(aws.Config{Region: "us-east-1"}, "/x")
	if p.Client.Options().RetryMaxAttempts != 1 {
		t.Fatal(p.Client.Options().RetryMaxAttempts)
	}
}

func TestUnit(t *testing.T) {
	for u, want := range map[string]cwtypes.StandardUnit{"Count": cwtypes.StandardUnitCount, "Bytes": cwtypes.StandardUnitBytes,
		"Seconds": cwtypes.StandardUnitSeconds, "Percent": cwtypes.StandardUnitPercent, "": cwtypes.StandardUnitNone} {
		if got := unit(u); got != want {
			t.Errorf("%q: %v", u, got)
		}
	}
}

// An empty or oversized secret value is secretsrc.ErrInvalid through the
// real source (%w), not a failed read.
func TestSecretInvalid(t *testing.T) {
	stub := func(body string) *secretsmanager.Client {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return secretsmanager.New(secretsmanager.Options{Region: "us-east-1", BaseEndpoint: aws.String(srv.URL), RetryMaxAttempts: 1,
			Credentials: credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "test", "")})
	}
	s := &Secret{Client: stub(`{"Name":"x","SecretString":""}`), ID: "x"}
	if _, err := s.Get(context.Background()); !errors.Is(err, secretsrc.ErrInvalid) {
		t.Fatalf("empty: %v", err)
	}
	s = &Secret{Client: stub(`{"Name":"x","SecretString":"` + strings.Repeat("a", 100) + `"}`), ID: "x", MaxSize: 99}
	if _, err := s.Get(context.Background()); !errors.Is(err, secretsrc.ErrInvalid) {
		t.Fatalf("too large: %v", err)
	}
	s.MaxSize = 100
	if b, err := s.Get(context.Background()); err != nil || len(b) != 100 {
		t.Fatalf("at the limit: %v", err)
	}
}
