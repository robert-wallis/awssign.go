/*
	Copyright © 2012, Robert Wallis <robert-wallis@ieee.org>
	See LICENSE file for more information.
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
func QueryRequest(aws_key, aws_secret, http_method, host, uri string, params url.Values) (*http.Response, error) {
	awsSign := AwsSign{
		AwsKey:     aws_key,
		AwsSecret:  aws_secret,
		HttpMethod: http_method,
		Host:       host,
		Uri:        uri,
		Params:     params,
	}
	// make sure all the params are signed, and add any extra required params
	awsSign.SignQuery()
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

// Signs your request by adding values to the AwsSign.Params
// including "Signature".
func (p *AwsSign) SignQuery() {
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
