// Copyright (C) 2012 Robert Wallis
// AWS Sign, just a quick function to sign AWS requests
// Example in aws_test.go func TestAwsSign
package awssign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"sort"
	"strings"
)

// aws_key = Your Amazon Web Services key.
// aws_secret = Your Amazon Web Services secret used to create the signature.
// http_verb = Usually GET, POST, PUT or DELETE.
// host = Example: "sns.us-east-1.amazonaws.com" but depends on service.
// uri = Maybe your bucket name or if you don't know use "/".
// params = Whatever parameters are required by the service you're using.
// 			If a param is used twice, separate by a "," with no space.
// returns = A new map[string]string that has all the stuff from params with
// 			some new values including "Signature".
func AwsSign(aws_key, aws_secret, http_verb, host, uri string,
	params map[string]string) map[string]string {
	// Guide from Amazon:
	// http://docs.amazonwebservices.com/AlexaTopSites/latest/index.html?CalculatingSignatures.html
	// StringToSign = HTTPVerb + "\n" +
	//                ValueOfHostHeaderInLowercase + "\n" +
	//                HTTPRequestURI + "\n" +
	//                CanonicalizedQueryString <from the preceding step>
	// Signature = Base64(SHA256(StringToSign))
	// make a copy of params to make this 'functional' or non-destructive
	out := make(map[string]string, len(params)+4)
	for k, v := range params {
		out[k] = v
	}
	// make sure the required params are added
	out["SignatureVersion"] = "2"
	out["SignatureMethod"] = "HmacSHA256"
	out["AWSAccessKeyId"] = aws_key

	// make sure the params are sorted
	sortedParamKeys := make([]string, len(out))
	i := 0
	for k, _ := range out {
		sortedParamKeys[i] = k
		i++
	}
	sort.Strings(sortedParamKeys)

	// build a query string out of the params
	canonicalizedQueryArray := make([]string, len(out))
	for i := 0; i < len(sortedParamKeys); i++ {
		k := sortedParamKeys[i]
		canonicalizedQueryArray[i] = k + "=" + escape(out[k])
	}
	canonicalizedQueryString := strings.Join(canonicalizedQueryArray, "&")

	// build the string that will be signed
	stringToSign := http_verb + "\n" +
		strings.ToLower(host) + "\n" +
		uri + "\n" +
		canonicalizedQueryString

	// sign it with the secret
	sha := hmac.New(sha256.New, []byte(aws_secret))
	io.WriteString(sha, stringToSign)
	signature := base64.StdEncoding.EncodeToString(sha.Sum(nil))

	// save the signature back into the params
	out["Signature"] = signature
	return out
}

// modified from net.url because shouldEscape is
// overriden with an encodeQueryComponent 'if'
// http://golang.org/src/pkg/net/url/url.go?s=4017:4682#L175
func escape(s string) string {
	spaceCount, hexCount := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if shouldEscape(c) {
			hexCount++
		}
	}

	if spaceCount == 0 && hexCount == 0 {
		return s
	}

	t := make([]byte, len(s)+2*hexCount)
	j := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case shouldEscape(c):
			t[j] = '%'
			t[j+1] = "0123456789ABCDEF"[c>>4]
			t[j+2] = "0123456789ABCDEF"[c&15]
			j += 3
		default:
			t[j] = s[i]
			j++
		}
	}
	return string(t)
}

// truncated from pkg net/url
// according to RFC 3986
func shouldEscape(c byte) bool {
	// §2.3 Unreserved characters (alphanum)
	if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' {
		return false
	}
	switch c {
	case '-', '_', '.', '~': // §2.3 Unreserved characters (mark)
		return false
	}
	return true
}
