/*
	AWS Sign, a tiny library to sign AWS requests
	Copyright (C) 2012 Robert Wallis

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	   http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
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

// aws_key = Your Amazon Web Services key.
// aws_secret = Your Amazon Web Services secret used to create the signature.
// http_method = HTTP "verb" usually GET, POST, PUT or DELETE.
// host = Example: "sns.us-east-1.amazonaws.com" but depends on service.
// uri = Maybe your bucket name or if you don't know use "/".
// params = Whatever parameters are required by the service you're using.
// 			If a param is used twice, separate by a "," with no space.
// returns = An http.Response object to parse on your own
func Request(aws_key, aws_secret, http_method, host, uri string, params url.Values) (*http.Response, error) {
	awsSign := AwsSign{
		AwsKey:     aws_key,
		AwsSecret:  aws_secret,
		HttpMethod: http_method,
		Host:       host,
		Uri:        uri,
		Params:     params,
	}
	// make sure all the params are signed, and add any extra required params
	awsSign.Sign()
	// no matter what we all have the same base
	baseURL := "https://" + host + uri
	switch {
	case "POST" == http_method || "PUT" == http_method:
		return http.PostForm(baseURL, awsSign.Params)
	case "GET" == http_method:
		return http.Get(baseURL + "?" + awsSign.Params.Encode())
	default:
		client := &http.Client{}
		req, err := http.NewRequest(http_method, baseURL+"?"+params.Encode(), nil)
		if err != nil {
			return nil, err
		}
		return client.Do(req)
	}
	// impossible
	return nil, nil
}

// This is an object so you can more quickly overwrite
// Params withp.Params having to pass them all around.
type AwsSign struct {
	AwsKey     string     // Your Amazon Web Services key.
	AwsSecret  string     // Your Amazon Web Services secret used to create the signature.
	HttpMethod string     // HTTP "verb" usually GET POST PUT or DELETE.
	Host       string     // Example: "sns.us-east-1.amazonaws.com" but depends on service.
	Uri        string     // Example: "/" for none, or "/bucket/object"
	Params     url.Values // The parameters required by the AWS service you're using.
	// If a param is used twice separate by a "" with no space.
}

// Signs your request by adding values to the 'params'
// including "Signature".
//
// aws_key = Your Amazon Web Services key.
// aws_secret = Your Amazon Web Services secret used to create the signature.
// http_method = HTTP "verb" usually GET, POST, PUT or DELETE.
// host = Example: "sns.us-east-1.amazonaws.com" but depends on service.
// uri = Maybe your bucket name or if you don't know use "/".
// params = Whatever parameters are required by the service you're using.
// 			If a param is used twice, separate by a "," with no space.
//
// usage:
//		signer := awssign.AwsSign{...}
//		url := signer.Params.Encode()
func (p *AwsSign) Sign() {
	// Guide from Amazon:
	// http://docs.amazonwebservices.com/AlexaTopSites/latest/index.html?CalculatingSignatures.html
	// StringToSign = HTTPVerb + "\n" +
	//                ValueOfHostHeaderInLowercase + "\n" +
	//                HTTPRequestURI + "\n" +
	//                CanonicalizedQueryString <from the preceding step>
	// Signature = Base64(SHA256(StringToSign))

	// make sure the required params are added
	p.Params.Set("SignatureVersion", "2")
	p.Params.Set("SignatureMethod", "HmacSHA256")
	p.Params.Set("AWSAccessKeyId", p.AwsKey)
	if "" == p.Params.Get("Timestamp") {
		p.Params.Set("Timestamp", time.Now().UTC().Format(time.RFC3339))
	}

	// make sure the params are sorted
	sortedParamKeys := make([]string, len(p.Params))
	i := 0
	for k, _ := range p.Params {
		sortedParamKeys[i] = k
		i++
	}
	sort.Strings(sortedParamKeys)

	// build a query string p.Params of the params
	canonicalizedQueryArray := make([]string, len(p.Params))
	for i := 0; i < len(sortedParamKeys); i++ {
		k := sortedParamKeys[i]
		// support multiple values, but don't encode the ,
		vlist := make([]string, len(p.Params[k]))
		for j := 0; j < len(p.Params[k]); j++ {
			vlist[j] = escape(p.Params[k][j])
		}
		// group multiple values by a comma
		vs := strings.Join(vlist, ",")
		canonicalizedQueryArray[i] = k + "=" + vs
	}
	canonicalizedQueryString := strings.Join(canonicalizedQueryArray, "&")

	// build the string that will be signed
	stringToSign := p.HttpMethod + "\n" +
		strings.ToLower(p.Host) + "\n" +
		p.Uri + "\n" +
		canonicalizedQueryString

	// sign it with the secret
	sha := hmac.New(sha256.New, []byte(p.AwsSecret))
	io.WriteString(sha, stringToSign)
	signature := base64.StdEncoding.EncodeToString(sha.Sum(nil))

	// save the signature back into the params
	p.Params.Set("Signature", signature)
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
	switch {
	// §2.3 Unreserved characters (alphanum)
	case 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9':
		return false
	// §2.3 Unreserved characters (mark)
	case '-' == c, '_' == c, '.' == c, '~' == c:
		return false
	}
	return true
}
