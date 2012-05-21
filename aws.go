// AWS Sign, just a quick function to sign AWS requests
package awssign

import (
	"encoding/base64"
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"sort"
	"strings"
	"net/url"
)

type AwsCredentials struct {
	Key string
	Secret string
}

// http://docs.amazonwebservices.com/AlexaTopSites/latest/index.html?CalculatingSignatures.html
// StringToSign = HTTPVerb + "\n" +
//                ValueOfHostHeaderInLowercase + "\n" +
//                HTTPRequestURI + "\n" +
//                CanonicalizedQueryString <from the preceding step>
// Signature = Base64(SHA256(StringToSign))

func AwsSign(creds AwsCredentials, httpVerb string, host string, uri string, params map[string]string) {
	// make sure the required params are added
	params["SignatureVersion"] = "2"
	params["SignatureMethod"] = "HmacSHA256"
	params["AWSAccessKeyId"] = creds.Key
	// make sure the params are sorted
	sortedParamKeys := make([]string, len(params))
	i := 0
	for k, _ := range params {
		sortedParamKeys[i] = k
		i++
	}
	sort.Strings(sortedParamKeys)
	// build a query string out of the params
	canonicalizedQueryArray := make([]string, len(params))
	for i := 0; i < len(sortedParamKeys); i++ {
		k := sortedParamKeys[i]
		canonicalizedQueryArray[i] = k + "=" + url.QueryEscape(params[k])
	}
	canonicalizedQueryString := strings.Join(canonicalizedQueryArray, "&")
	// build the string that will be signed
	stringToSign := httpVerb + "\n" +
		strings.ToLower(host) + "\n" +
		uri +
		canonicalizedQueryString
	sha := hmac.New(sha256.New, []byte(creds.Secret))
	io.WriteString(sha, stringToSign)
	signature := base64.StdEncoding.EncodeToString(sha.Sum(nil))
	params["Signature"] = signature
}
