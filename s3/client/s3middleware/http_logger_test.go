package s3middleware

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("HttpLogger", func() {
	var buf bytes.Buffer
	BeforeEach(func() {
		buf.Reset()
		logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
		slog.SetDefault(logger)
	})

	Context("when transport returns response,", func() {
		It("log with 's3 http request' message", func() {
			mockTransport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: 403,
					Body:       io.NopCloser(strings.NewReader("error")),
					Header: http.Header{
						"X-Amz-Request-Id":    []string{"request-id"},
						"X-Amz-Id-2":          []string{"extended-request-id"},
						"X-Amz-Error-Code":    []string{"SignatureDoesNotMatch"},
						"X-Amz-Error-Message": []string{"The request signature we calculated does not match"},
					},
					ContentLength: 5,
				}, nil
			})
			loggingTransport := NewS3LoggingTransport(mockTransport)
			req := httptest.NewRequest("GET", "http://example.com/test", nil)
			req.Header.Set("Host", "example.com")
			req.Header.Set("Range", "bytes=0-2")
			req.Header.Set("X-Amz-Content-Sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
			req.Header.Set("X-Amz-Date", "20250909T080000Z")
			req.Header.Set("X-Amz-Security-Token", "super-secret-session-token")
			req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20250909/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=deadbeef")
			_, _ = loggingTransport.RoundTrip(req) //nolint:errcheck
			logs := buf.String()

			Expect(logs).To(ContainSubstring(`"msg":"s3 http request"`))
			Expect(logs).To(ContainSubstring(`"host":"example.com"`))
			Expect(logs).To(ContainSubstring(`"signing_algorithm":"AWS4-HMAC-SHA256"`))
			Expect(logs).To(ContainSubstring(`"signed_headers":"host;x-amz-content-sha256;x-amz-date"`))
			Expect(logs).To(ContainSubstring(`"credential_scope":"20250909/us-east-1/s3/aws4_request"`))
			Expect(logs).To(ContainSubstring(`"x_amz_date":"20250909T080000Z"`))
			Expect(logs).To(ContainSubstring(`"x_amz_error_code":"SignatureDoesNotMatch"`))
			Expect(logs).ToNot(ContainSubstring(`authorization`))
			Expect(logs).ToNot(ContainSubstring(`deadbeef`))
			Expect(logs).ToNot(ContainSubstring(`super-secret-session-token`))
			Expect(logs).ToNot(ContainSubstring(`AKIAIOSFODNN7EXAMPLE`))
		})
	})

	Context("when transport returns error,", func() {
		It("log with 's3 http request failed' message", func() {
			hostNotFound := errors.New("dial tcp: lookup example.com: no such host")

			mockTransport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				return nil, hostNotFound
			})
			loggingTransport := NewS3LoggingTransport(mockTransport)
			req := httptest.NewRequest("GET", "http://example.com/test", nil)
			_, _ = loggingTransport.RoundTrip(req) //nolint:errcheck
			logs := buf.String()
			Expect(logs).To(ContainSubstring(`"msg":"s3 http request failed"`))
			Expect(logs).To(ContainSubstring(`"method":"GET"`))
			Expect(logs).To(ContainSubstring(`"error"`))
			Expect(logs).To(ContainSubstring("no such host"))
		})
	})
})
