package s3middleware

import (
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func NewS3LoggingTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}

	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		start := time.Now()
		resp, err := base.RoundTrip(req)
		duration := time.Since(start)

		attrs := []any{
			"method", req.Method,
			"url", req.URL.String(),
			"host", requestHost(req),
			"request_content_length", req.ContentLength,
			"duration_ms", duration.Milliseconds(),
		}

		for k, v := range signingFields(req) {
			attrs = append(attrs, k, v)
		}

		if resp != nil {
			for k, v := range parseResponseFields(resp) {
				attrs = append(attrs, k, v)
			}
		}

		if err != nil {
			attrs = append(attrs, "error", err.Error())
			slog.Error("s3 http request failed", attrs...)
			return resp, err
		}

		slog.Debug("s3 http request", attrs...)

		return resp, nil
	})
}

func requestHost(req *http.Request) string {
	if req.Host != "" {
		return req.Host
	}
	if req.URL != nil {
		return req.URL.Host
	}
	return ""
}

// signingFields extracts safe signing metadata for signature/header debugging.
// Authorization, signatures, and security tokens are never logged.
func signingFields(req *http.Request) map[string]any {
	fields := make(map[string]any)

	if host := firstHeader(req, "Host"); host != "" {
		fields["request_host_header"] = host
	}
	if date := firstHeader(req, "X-Amz-Date"); date != "" {
		fields["x_amz_date"] = date
	}
	if payloadHash := firstHeader(req, "X-Amz-Content-Sha256"); payloadHash != "" {
		fields["x_amz_content_sha256"] = payloadHash
	}
	if rangeHeader := firstHeader(req, "Range"); rangeHeader != "" {
		fields["range"] = rangeHeader
	}
	if req.Header.Get("X-Amz-Security-Token") != "" {
		fields["session_token_present"] = true
	}

	if authorization := req.Header.Get("Authorization"); authorization != "" {
		if algorithm, credentialScope, signedHeaders, accessKeyPrefix := parseSigningContext(authorization); algorithm != "" || credentialScope != "" || signedHeaders != "" || accessKeyPrefix != "" {
			if algorithm != "" {
				fields["signing_algorithm"] = algorithm
			}
			if accessKeyPrefix != "" {
				fields["access_key_prefix"] = accessKeyPrefix
			}
			if credentialScope != "" {
				fields["credential_scope"] = credentialScope
			}
			if signedHeaders != "" {
				fields["signed_headers"] = signedHeaders
			}
		}
	}

	return fields
}

func parseResponseFields(resp *http.Response) map[string]any {
	responseFields := make(map[string]any)
	responseFields["status_code"] = resp.StatusCode
	responseFields["response_content_length"] = resp.ContentLength
	responseFields["request_id"] = resp.Header.Get("x-amz-request-id")
	responseFields["extended_request_id"] = resp.Header.Get("x-amz-id-2")

	if errorCode := resp.Header.Get("x-amz-error-code"); errorCode != "" {
		responseFields["x_amz_error_code"] = errorCode
	}
	if errorMessage := resp.Header.Get("x-amz-error-message"); errorMessage != "" {
		responseFields["x_amz_error_message"] = errorMessage
	}

	return responseFields
}

func firstHeader(req *http.Request, name string) string {
	return req.Header.Get(name)
}

func parseSigningContext(authorization string) (algorithm, credentialScope, signedHeaders, accessKeyPrefix string) {
	if !strings.HasPrefix(authorization, "AWS4-HMAC-SHA256 ") {
		return "", "", "", ""
	}

	algorithm = "AWS4-HMAC-SHA256"
	payload := strings.TrimPrefix(authorization, "AWS4-HMAC-SHA256 ")
	for _, part := range splitAuthorizationParts(payload) {
		switch {
		case strings.HasPrefix(part, "Credential="):
			accessKeyPrefix, credentialScope = parseCredential(strings.TrimPrefix(part, "Credential="))
		case strings.HasPrefix(part, "SignedHeaders="):
			signedHeaders = strings.TrimPrefix(part, "SignedHeaders=")
		}
	}

	return algorithm, credentialScope, signedHeaders, accessKeyPrefix
}

func parseCredential(credential string) (accessKeyPrefix, credentialScope string) {
	slashIdx := strings.Index(credential, "/")
	if slashIdx <= 0 {
		return "", ""
	}

	accessKey := credential[:slashIdx]
	credentialScope = credential[slashIdx+1:]
	if len(accessKey) <= 4 {
		return accessKey, credentialScope
	}

	return accessKey[:4] + "...", credentialScope
}

func splitAuthorizationParts(payload string) []string {
	parts := strings.Split(payload, ", ")
	if len(parts) == 1 {
		parts = strings.Split(payload, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
	}
	return parts
}
