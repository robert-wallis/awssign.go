/*
	Copyright © 2012, Robert Wallis <robert-wallis@ieee.org>
	See LICENSE file for more information.

	-------------------------------------------------------------------------

	Some AWS services need to send params via Query string, and be signed 
	differently than REST services:

	Guide from Amazon:
	http://docs.amazonwebservices.com/AmazonS3/2006-03-01/dev/RESTAuthentication.html

		Authorization = "AWS" + " " + AWSAccessKeyId + ":" + Signature;

		CanonicalizedResource = [ "/" + Bucket ] +
			<HTTP-Request-URI, from the protocol name up to the query string> +
			[ sub-resource, if present. For example "?acl", "?location", "?logging", or "?torrent"];

		CanonicalizedAmzHeaders = <described below>

		StringToSign = HTTP-Verb + "\n" +
			Content-MD5 + "\n" +
			Content-Type + "\n" +
			Date + "\n" +
			CanonicalizedAmzHeaders +
			CanonicalizedResource;

		
		Signature = Base64( HMAC-SHA1( YourSecretAccessKeyID, UTF-8-Encoding-Of( StringToSign ) ) );
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
func RESTRequest(aws_key, aws_secret, http_method, host, uri string, params url.Values) (*http.Response, error) {
	awsSign := AwsSign{
		AwsKey:     aws_key,
		AwsSecret:  aws_secret,
		HttpMethod: http_method,
		Host:       host,
		Uri:        uri,
		Params:     params,
	}
	// make sure all the params are signed, and add any extra required params
	awsSign.SignREST()
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
func (p *AwsSign) SignREST() {
	// make sure the required params are added
	has_date := false

	// pull out the relevant params for signing
	amz_headers := make(url.Values, len(p.Params))
	for key, val := range p.Params {
		lower := strings.ToLower(key)
		switch{
		case strings.HasPrefix(lower, "x-amz"):
			amz_headers[lower] = val
		case lower == "content-md5":
			amz_headers[lower] = val
		case lower == "content-type":
			amz_headers[lower] = val
		case lower == "date":
			has_date = true
		case lower == "x-amz-date":
			has_date = true
		}
	}

	// add required params
	if false == has_date {
		date := time.Now().UTC().Format(time.RFC3339)
		amz_headers.Add("date", date)
	}

	// make sure the amz_headres are sorted
	sorted_param_keys := make([]string, len(amz_headers))
	i := 0
	for k, _ := range amz_headers {
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
	canonicalized_query_string := strings.Join(canonicalized_query_array, "&")

	// build the string that will be signed
	stringToSign := p.HttpMethod + "\n" +
		strings.ToLower(p.Host) + "\n" +
		p.Uri + "\n" +
		canonicalized_query_string

	// sign it with the secret
	sha := hmac.New(sha256.New, []byte(p.AwsSecret))
	io.WriteString(sha, stringToSign)
	signature := base64.StdEncoding.EncodeToString(sha.Sum(nil))

	// save the signature back into the params
	p.Params.Set("Signature", signature)
}
