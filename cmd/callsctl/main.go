// Command callsctl is the calling service's operator tool
// (CALLING-SERVICE §8.3, §11).
//
//	callsctl secret new                 print a first secret document with one fresh secret
//	callsctl secret rotate < old        print old with a fresh secret added and made current;
//	                                    the old one stays, so credentials it signed still work
//	callsctl secret drop <id> < old     print old without a retired secret (a day after the
//	                                    rotation: longer than a credential's 6 hours)
//	callsctl secret list < doc          print the ids and which is current (never a value)
//	callsctl credential [-ttl 6h] [-turn-host turn.staging.vettid.org] < doc
//	                                    print a TEST credential signed with the current secret,
//	                                    for the operator's checks after a deployment (§11 item 3)
//	                                    and the exit test's short-lived credential (CALLS-PLAN
//	                                    §13.4 step 12). For the operator only: never give one to
//	                                    a member's device.
//	callsctl check <username> <credential> < doc
//	                                    say whether the server, holding doc, would accept them now
//
// The output of new, rotate and drop IS THE SECRET: pipe it straight into
// the secret store (aws secretsmanager put-secret-value --secret-id
// vettid-org/staging/calls/turn-secret --secret-string file:///dev/stdin),
// never into a file or a terminal log. A secret is never deleted and
// created again (§8.3).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/vettid/vettid-calls/internal/issuer"
	"github.com/vettid/vettid-calls/internal/turncred"
)

const usage = `usage:
  callsctl secret new | rotate | drop <id> | list     (the document on stdin for rotate, drop, list)
  callsctl credential [-ttl 6h] [-turn-host host]     (the document on stdin)
  callsctl check <username> <credential>              (the document on stdin)`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, time.Now))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, now func() time.Time) int {
	die := func(err error) int {
		fmt.Fprintln(stderr, "callsctl:", err)
		return 1
	}
	read := func() (*turncred.Set, error) {
		b, err := io.ReadAll(io.LimitReader(stdin, turncred.MaxDocument+1))
		if err != nil {
			return nil, err
		}
		return turncred.ParseSet([]byte(strings.TrimSpace(string(b))))
	}
	emit := func(s *turncred.Set) int {
		b, err := s.Marshal()
		if err != nil {
			return die(err)
		}
		fmt.Fprintln(stdout, string(b))
		return 0
	}
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	switch args[0] {
	case "secret":
		if len(args) < 2 {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		switch {
		case args[1] == "new" && len(args) == 2:
			s, err := turncred.NewSet(now(), nil)
			if err != nil {
				return die(err)
			}
			return emit(s)
		case args[1] == "rotate" && len(args) == 2:
			s, err := read()
			if err != nil {
				return die(err)
			}
			if err := s.Rotate(now(), nil); err != nil {
				return die(err)
			}
			return emit(s)
		case args[1] == "drop" && len(args) == 3:
			s, err := read()
			if err != nil {
				return die(err)
			}
			if err := s.Drop(args[2]); err != nil {
				return die(err)
			}
			return emit(s)
		case args[1] == "list" && len(args) == 2:
			s, err := read()
			if err != nil {
				return die(err)
			}
			for _, id := range s.IDs() {
				mark := ""
				if id == s.Current {
					mark = "  (current)"
				}
				fmt.Fprintln(stdout, id+mark)
			}
			return 0
		}
	case "credential":
		fs := flag.NewFlagSet("credential", flag.ContinueOnError)
		fs.SetOutput(stderr)
		ttl := fs.Duration("ttl", turncred.Lifetime, "lifetime of the test credential (at most 6h)")
		host := fs.String("turn-host", "turn.staging.vettid.org", "the TURN server's name")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			return 2
		}
		if *ttl <= 0 || *ttl > turncred.Lifetime {
			return die(fmt.Errorf("-ttl must be more than 0 and at most %s", turncred.Lifetime))
		}
		if err := issuer.ValidHost(*host); err != nil {
			return die(err)
		}
		s, err := read()
		if err != nil {
			return die(err)
		}
		c, err := turncred.Make(s.CurrentSecret(), now(), *ttl, nil)
		if err != nil {
			return die(err)
		}
		out := struct {
			URLs []string `json:"urls"`
			turncred.Credential
			Note string `json:"note"`
		}{[]string{"stun:" + *host + ":3478", "turn:" + *host + ":3478?transport=udp", "turn:" + *host + ":3478?transport=tcp"},
			c, "TEST credential for the operator; expires at exp"}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Fprintln(stdout, string(b))
		return 0
	case "check":
		if len(args) != 3 {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		s, err := read()
		if err != nil {
			return die(err)
		}
		if turncred.Check(s.Ordered(), args[1], args[2], now()) {
			fmt.Fprintln(stdout, "accepted")
			return 0
		}
		fmt.Fprintln(stdout, "refused")
		return 1
	}
	fmt.Fprintln(stderr, usage)
	return 2
}
