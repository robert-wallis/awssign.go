/*
	Copyright © 2012, Robert Wallis <robert-wallis@ieee.org>
	See LICENSE file for more information.

	-------------------------------------------------------------------------

	Guide from Amazon:
	http://docs.amazonwebservices.com/general/latest/gr/signature-version-4.html
*/
package awssign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type AwsSignatureV4 struct {
	AwsKey     string     // Your Amazon Web Services key.
	AwsSecret  string     // Your Amazon Web Services secret used to create the signature.
	HttpMethod string     // HTTP "verb" usually GET POST PUT or DELETE.
	Host       string     // Example: "sns.us-east-1.amazonaws.com" but depends on service.
	Uri        string     // Example: "/" for none, or "/bucket/object"
	Params     url.Values // The parameters required by the AWS service you're using.
}

// aws_key = Your Amazon Web Services key.
// aws_secret = Your Amazon Web Services secret used to create the signature.
// http_method = HTTP "verb" usually GET, POST, PUT or DELETE.
// host = Example: "sns.us-east-1.amazonaws.com" but depends on service.
// uri = Maybe your bucket name or if you don't know use "/".
// params = Whatever parameters are required by the service you're using.
// 			If a param is used twice, separate by a "," with no space.
// returns = An http.Response object to parse on your own
func RestV4Request(aws_key, aws_secret, http_method, host, uri string, params url.Values) (*http.Response, error) {
	aws_sign := AwsSignatureV4{
		AwsKey:     aws_key,
		AwsSecret:  aws_secret,
		HttpMethod: http_method,
		Host:       host,
		Uri:        uri,
		Params:     params,
	}
	// prefer the Request because it can handle tons of params vs the query string
	return aws_sign.Request()
}

// return a query string that you could use on the client side
// like a special url to a s3 object that has a timeout for downloads
func (p *AwsSignatureV4) QueryString() string {
	base_url := "https://" + p.Host + p.Uri
	signature := p.sign()
	p.Params.Set("Signature", signature)
	return base_url + "?" + p.Params.Encode()
}

// make a new http.Request object, executes and returns the response
// puts all the params together in the HTTP header (as opposed to the query string)
func (p *AwsSignatureV4) Request() (*http.Response, error) {
	base_url := "https://" + p.Host + p.Uri
	client := &http.Client{}
	req, err := http.NewRequest(p.HttpMethod, base_url+"?"+p.Params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

// "Task 3" http://docs.amazonwebservices.com/general/latest/gr/sigv4-calculate-signature.html
// signs without adding "Signature" to the internal Params
func (p *AwsSignatureV4) sign() string {
	p.addRequiredParams()
	canonical_request := p.canonicalRequest()
	string_to_sign := p.stringToSign(canonical_request)

	// sign it with the secret
	sha := hmac.New(sha256.New, []byte(p.AwsSecret))
	io.WriteString(sha, string_to_sign)
	signature := base64.StdEncoding.EncodeToString(sha.Sum(nil))

	return signature
}

// sets the Date header
func (p *AwsSignatureV4) addRequiredParams() {
	date := time.Now().UTC().Format(time.RFC3339)
	p.Params.Set("Date", date)
}

// "Task 1" http://docs.amazonwebservices.com/general/latest/gr/sigv4-create-canonical-request.html
func (p *AwsSignatureV4) canonicalRequest() string {
	canonical_headers, signed_headers := p.canonicalAndSignedHeaders()
	return p.HttpMethod + "\n" +
		p.Uri + "\n" +
		"\n" + // canonical query string, skipped on purpose
		canonical_headers + "\n" +
		signed_headers + "\n" +
		// TODO: signed payload
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}

// creates a canonical (sorted) string for the request
// and encodes it in Amazon's particular way
func (p *AwsSignatureV4) canonicalQueryString() string {
	// make sure the amz_headres are sorted
	sorted_param_keys := make([]string, len(p.Params))
	i := 0
	for k, _ := range p.Params {
		sorted_param_keys[i] = k
		i++
	}
	sort.Strings(sorted_param_keys)

	// build a query string p.Params of the params
	canonicalized_query_array := make([]string, len(p.Params))
	for i := 0; i < len(sorted_param_keys); i++ {
		k := sorted_param_keys[i]
		// support multiple values, but don't encode the ,
		vlist := make([]string, len(p.Params[k]))
		for j := 0; j < len(p.Params[k]); j++ {
			vlist[j] = escape(p.Params[k][j])
		}
		// group multiple values by a comma
		vs := strings.Join(vlist, ",")
		canonicalized_query_array[i] = k + "=" + vs
	}
	return strings.Join(canonicalized_query_array, "&")
}

func (p *AwsSignatureV4) canonicalAndSignedHeaders() (string, string) {
	// make sure the amz_headres are sorted
	sorted_param_keys := make([]string, len(p.Params))
	i := 0
	for k, _ := range p.Params {
		sorted_param_keys[i] = k
		i++
	}
	sort.Strings(sorted_param_keys)

	// build a query string p.Params of the params
	canonicalized_query_array := make([]string, len(p.Params))
	signed_headers_array := make([]string, len(p.Params))
	for i := 0; i < len(sorted_param_keys); i++ {
		k := sorted_param_keys[i]
		// support multiple values, but don't encode the ,
		vlist := make([]string, len(p.Params[k]))
		for j := 0; j < len(p.Params[k]); j++ {
			vlist[j] = p.Params[k][j]
		}
		// group multiple values by a comma
		vs := strings.Join(vlist, ",")
		canonicalized_query_array[i] = strings.ToLower(k) + ":" + vs + "\n"
		signed_headers_array[i] = strings.ToLower(k)
	}
	return strings.Join(canonicalized_query_array, ""), strings.Join(signed_headers_array, ";")
}

// "Task 2" http://docs.amazonwebservices.com/general/latest/gr/sigv4-create-string-to-sign.html
// takes the canonicalized string, and returns the string that will need to be signed
func (p *AwsSignatureV4) stringToSign(canonical_request string) string {
	// build the string that will be signed
	return p.HttpMethod + "\n" +
		strings.ToLower(p.Host) + "\n" +
		p.Uri + "\n" +
		canonical_request
}
