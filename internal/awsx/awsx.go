// Package awsx is this repository's use of AWS: reading the TURN secret
// from Secrets Manager (CALLING-SERVICE §8.3), reading the TURN server's
// TLS status from SSM (§8.5) and putting metrics into CloudWatch (§10). Both binaries use it: the issuer with its function
// role, turn-agent with the instance role.
//
// The secret is encrypted under alias/vettid-org-calls; Secrets Manager
// decrypts it for the role, so it exists in plaintext only in the
// process's memory (and, for coturn, in its configuration on a tmpfs).
package awsx

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/vettid/vettid-calls/internal/metrics"
	"github.com/vettid/vettid-calls/internal/secretsrc"
	"github.com/vettid/vettid-calls/internal/turncred"
	"github.com/vettid/vettid-calls/internal/turnsstatus"
)

// Load returns the SDK configuration from the standard chain (the
// function's or the instance's role) for region.
func Load(ctx context.Context, region string) (aws.Config, error) {
	return awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
}

// Secret reads one secret by id (secretsrc.Source).
type Secret struct {
	Client *secretsmanager.Client
	ID     string
	// MaxSize bounds the value (default turncred.MaxDocument; the TLS
	// certificate's document is tlscert.MaxDocument).
	MaxSize int
}

// NewSecret returns the Secrets Manager source of secret id.
func NewSecret(cfg aws.Config, id string) *Secret {
	return &Secret{Client: secretsmanager.NewFromConfig(cfg), ID: id}
}

// Get implements secretsrc.Source. Errors name the secret, never its
// content.
func (s *Secret) Get(ctx context.Context) ([]byte, error) {
	out, err := s.Client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(s.ID)})
	var nf *smtypes.ResourceNotFoundException
	switch {
	case errors.As(err, &nf):
		return nil, secretsrc.ErrNotFound
	case err != nil:
		return nil, fmt.Errorf("awsx: reading secret %s failed", s.ID)
	}
	var b []byte
	if out.SecretString != nil {
		b = []byte(*out.SecretString)
	} else {
		b = out.SecretBinary
	}
	max := s.MaxSize
	if max == 0 {
		max = turncred.MaxDocument
	}
	if len(b) == 0 || len(b) > max {
		return nil, fmt.Errorf("awsx: secret %s is empty or too large", s.ID)
	}
	return b, nil
}

// Parameter reads one SSM parameter by name: the TURN server's TLS status
// (CALLING-SERVICE 0.3.0 §8.5, turnsstatus.Source). It is a String, not
// a secret, so it is read without decryption.
type Parameter struct {
	Client *ssm.Client
	Name   string
}

// NewParameter returns the SSM source of parameter name. One attempt per
// read, no SDK retries: the read is on a request's path, bounded by
// turnsstatus.ReadTimeout, and a failed read keeps the last status.
func NewParameter(cfg aws.Config, name string) *Parameter {
	return &Parameter{Client: ssm.NewFromConfig(cfg, func(o *ssm.Options) { o.RetryMaxAttempts = 1 }), Name: name}
}

// Get implements turnsstatus.Source. Errors name the parameter.
func (p *Parameter) Get(ctx context.Context) ([]byte, error) {
	out, err := p.Client.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(p.Name)})
	var nf *ssmtypes.ParameterNotFound
	switch {
	case errors.As(err, &nf):
		return nil, turnsstatus.ErrNotFound
	case err != nil:
		return nil, fmt.Errorf("awsx: reading parameter %s failed", p.Name)
	case out.Parameter == nil || out.Parameter.Value == nil:
		return nil, turnsstatus.ErrNotFound
	}
	return []byte(*out.Parameter.Value), nil
}

// Put implements turnagent.StatusPutter: it overwrites the parameter's
// value (the stack makes the parameter, a String; the instance's role may
// put only it).
func (p *Parameter) Put(ctx context.Context, value []byte) error {
	_, err := p.Client.PutParameter(ctx, &ssm.PutParameterInput{Name: aws.String(p.Name), Value: aws.String(string(value)),
		Overwrite: aws.Bool(true)})
	if err != nil {
		return fmt.Errorf("awsx: putting parameter %s failed", p.Name)
	}
	return nil
}

// CloudWatch puts metrics with PutMetricData (metrics.Sink). Standard
// resolution: CloudWatch keeps them per minute, so no datum outlives its
// minute as a separate record. Used where the process cannot flush on a
// timer (the issuer as a function: it puts after each request) or has no
// log shipping (turn-agent: the container runs without a log driver).
type CloudWatch struct {
	Client *cloudwatch.Client
}

// NewCloudWatch returns the CloudWatch sink for cfg.
func NewCloudWatch(cfg aws.Config) *CloudWatch {
	return &CloudWatch{Client: cloudwatch.NewFromConfig(cfg)}
}

// maxPerCall is PutMetricData's limit of data per call.
const maxPerCall = 1000

// Put implements metrics.Sink.
func (c *CloudWatch) Put(ctx context.Context, namespace string, ts time.Time, data []metrics.Datum) error {
	in := make([]cwtypes.MetricDatum, 0, len(data))
	for _, d := range data {
		md := cwtypes.MetricDatum{MetricName: aws.String(d.Name), Timestamp: aws.Time(ts),
			Value: aws.Float64(d.Value), Unit: unit(d.Unit), StorageResolution: aws.Int32(60)}
		for _, dm := range d.Dims {
			md.Dimensions = append(md.Dimensions, cwtypes.Dimension{Name: aws.String(dm.Name), Value: aws.String(dm.Value)})
		}
		in = append(in, md)
	}
	for len(in) > 0 {
		n := min(len(in), maxPerCall)
		if _, err := c.Client.PutMetricData(ctx, &cloudwatch.PutMetricDataInput{
			Namespace: aws.String(namespace), MetricData: in[:n]}); err != nil {
			return errors.New("awsx: PutMetricData failed")
		}
		in = in[n:]
	}
	return nil
}

func unit(u string) cwtypes.StandardUnit {
	switch u {
	case "Count":
		return cwtypes.StandardUnitCount
	case "Bytes":
		return cwtypes.StandardUnitBytes
	case "Seconds":
		return cwtypes.StandardUnitSeconds
	case "Percent":
		return cwtypes.StandardUnitPercent
	default:
		return cwtypes.StandardUnitNone
	}
}
