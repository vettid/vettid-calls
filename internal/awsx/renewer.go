package awsx

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

// Route53TXT writes and deletes one TXT record in a hosted zone: the
// renewer's DNS-01 record (CALLING-SERVICE 0.3.0 §8.5). Its role may
// change only that record.
type Route53TXT struct {
	Client *route53.Client
	ZoneID string
	// Poll is the wait between GetChange calls (default 5 s).
	Poll time.Duration
}

// NewRoute53TXT returns the record writer for zone.
func NewRoute53TXT(cfg aws.Config, zoneID string) *Route53TXT {
	return &Route53TXT{Client: route53.NewFromConfig(cfg), ZoneID: zoneID}
}

// txtTTL is short: the record lives for one challenge.
const txtTTL = 60

func (r *Route53TXT) change(ctx context.Context, action r53types.ChangeAction, name, value string) (*route53.ChangeResourceRecordSetsOutput, error) {
	return r.Client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(r.ZoneID),
		ChangeBatch: &r53types.ChangeBatch{Changes: []r53types.Change{{
			Action: action,
			ResourceRecordSet: &r53types.ResourceRecordSet{Name: aws.String(name), Type: r53types.RRTypeTxt, TTL: aws.Int64(txtTTL),
				ResourceRecords: []r53types.ResourceRecord{{Value: aws.String(`"` + value + `"`)}}},
		}}},
	})
}

// Upsert implements renewer.DNS.
func (r *Route53TXT) Upsert(ctx context.Context, name, value string) (string, error) {
	out, err := r.change(ctx, r53types.ChangeActionUpsert, name, value)
	if err != nil {
		return "", fmt.Errorf("awsx: writing the TXT record of %s failed", name)
	}
	return aws.ToString(out.ChangeInfo.Id), nil
}

// WaitInSync implements renewer.DNS: until Route 53 reports the change
// INSYNC, or ctx ends.
func (r *Route53TXT) WaitInSync(ctx context.Context, change string) error {
	poll := r.Poll
	if poll <= 0 {
		poll = 5 * time.Second
	}
	for {
		out, err := r.Client.GetChange(ctx, &route53.GetChangeInput{Id: aws.String(change)})
		if err == nil && out.ChangeInfo.Status == r53types.ChangeStatusInsync {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("awsx: the TXT record did not become INSYNC in time")
		case <-time.After(poll):
		}
	}
}

// Delete implements renewer.DNS. A record that is not there (the write
// failed) is not an error.
func (r *Route53TXT) Delete(ctx context.Context, name, value string) error {
	_, err := r.change(ctx, r53types.ChangeActionDelete, name, value)
	var bad *r53types.InvalidChangeBatch
	if errors.As(err, &bad) && strings.Contains(strings.ToLower(aws.ToString(bad.Message)), "not found") {
		return nil
	}
	if err != nil {
		return fmt.Errorf("awsx: deleting the TXT record of %s failed", name)
	}
	return nil
}

// Secrets reads and puts secrets by id (renewer.Secrets): no create, no
// delete. Values are bounded by MaxSize.
type Secrets struct {
	Client  *secretsmanager.Client
	MaxSize int
}

// NewSecrets returns the Secrets Manager reader and writer.
func NewSecrets(cfg aws.Config, maxSize int) *Secrets {
	return &Secrets{Client: secretsmanager.NewFromConfig(cfg), MaxSize: maxSize}
}

// Get implements renewer.Secrets.
func (s *Secrets) Get(ctx context.Context, id string) ([]byte, error) {
	return (&Secret{Client: s.Client, ID: id, MaxSize: s.MaxSize}).Get(ctx)
}

// Put implements renewer.Secrets: a new current version.
func (s *Secrets) Put(ctx context.Context, id string, value []byte) error {
	if len(value) == 0 || len(value) > s.MaxSize {
		return fmt.Errorf("awsx: the value for %s is empty or too large", id)
	}
	_, err := s.Client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{SecretId: aws.String(id), SecretString: aws.String(string(value))})
	var nf *smtypes.ResourceNotFoundException
	if errors.As(err, &nf) {
		return fmt.Errorf("awsx: secret %s does not exist (the operator creates it)", id)
	}
	if err != nil {
		return fmt.Errorf("awsx: putting secret %s failed", id)
	}
	return nil
}
