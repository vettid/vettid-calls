package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

// lambdaStart is lambda.Start (the function's runtime loop).
func lambdaStart(h any) { lambda.Start(h) }

// lambdaHandler adapts the issuer to a Lambda function URL (payload
// format 2.0), the origin CloudFront forwards calls.<stage>.vettid.org to
// (CALLING-SERVICE §8.2). after runs once the answer is made and before it
// is returned.
//
// The request's source address (RequestContext.HTTP.SourceIP) is never
// read. A function URL joins repeated headers with commas; a request with
// two X-VettID-Attestation headers therefore arrives as one value that is
// not base64, and is refused as attestation_invalid, as two headers are.
func lambdaHandler(h http.Handler, after func(context.Context)) func(context.Context, events.LambdaFunctionURLRequest) (events.LambdaFunctionURLResponse, error) {
	return func(ctx context.Context, ev events.LambdaFunctionURLRequest) (events.LambdaFunctionURLResponse, error) {
		body := []byte(ev.Body)
		if ev.IsBase64Encoded {
			b, err := base64.StdEncoding.DecodeString(ev.Body)
			if err != nil {
				return events.LambdaFunctionURLResponse{StatusCode: http.StatusBadRequest,
					Headers: map[string]string{"Content-Type": "application/json"},
					Body:    `{"code":"bad_request","message":"malformed request"}` + "\n"}, nil
			}
			body = b
		}
		path := ev.RawPath
		if path == "" {
			path = "/"
		}
		r, err := http.NewRequestWithContext(ctx, ev.RequestContext.HTTP.Method, path, bytes.NewReader(body))
		if err != nil {
			return events.LambdaFunctionURLResponse{StatusCode: http.StatusBadRequest}, nil
		}
		for k, v := range ev.Headers {
			r.Header.Set(k, v)
		}
		r.ContentLength = int64(len(body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if after != nil {
			after(ctx)
		}
		hdr := map[string]string{}
		for k, v := range w.Header() {
			hdr[k] = strings.Join(v, ", ")
		}
		return events.LambdaFunctionURLResponse{StatusCode: w.Code, Headers: hdr, Body: w.Body.String()}, nil
	}
}
