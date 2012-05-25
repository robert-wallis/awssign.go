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
	"testing"
	"net/url"
)

var aws_key = "EXAMPLE+AWS+KEY"
var aws_secret = "EXAMPLE+AWS+SECRET"
var sns_host = "sns.us-east-1.amazonaws.com"
var test_host = "my.verbalink.com"
var test_url = "/awssign.go/test"

func TestSign(t *testing.T) {
	// secret: EXAMPLE+AWS+SECRET
	// http://sns.us-east-1.amazonaws.com/?
	// 		AWSAccessKeyId=EXAMPLE%2BAWS%2BKEY&
	//		Action=Publish&
	//		ContentType=JSON&
	//		Message=Hi%20Test&
	//		SignatureMethod=HmacSHA256&
	//		SignatureVersion=2&
	//		Timestamp=2012-05-21T21%3A16%3A38Z&
	//		TopicArn=arn%3Aaws%3Asns%3Aus-east-1%3A123456789%3Aexample-message&
	//		Version=2010-03-31&
	//		Signature=NU%2FUNneSfY3qMk78Wetdp%2B7xGyM2uelG%2Bnsr17OEzSU%3D
	var signature = "NU/UNneSfY3qMk78Wetdp+7xGyM2uelG+nsr17OEzSU="
	params := map[string][]string{
		"Message":     {"Hi Test"},
		"TopicArn":    {"arn:aws:sns:us-east-1:123456789:example-message"},
		"Timestamp":   {"2012-05-21T21:16:38Z"},
		"Version":     {"2010-03-31"},
		"Action":      {"Publish"},
		"ContentType": {"JSON"}, // verified sig with "boto", that's why this is here
	}
	a := AwsSign{
		aws_key,
		aws_secret,
		"GET",
		sns_host,
		"/",
		params,
	}
	// do the actual sign
	a.Sign()

	// verify it worked
	if v, ok := a.Params["SignatureVersion"]; !ok || "2" != v[0] {
		t.Errorf("SignatureVersion expecting \"%s\" received \"%s\"", "2", v[0])
	}
	if v, ok := a.Params["SignatureMethod"]; !ok || "HmacSHA256" != v[0] {
		t.Errorf("SignatureMethod expecting \"%s\" received \"%s\"", "HmacSHA256", v[0])
	}
	if v, ok := a.Params["Signature"]; !ok || signature != v[0] {
		t.Errorf("Sigunature expecting \"%s\" received \"%s\"", signature, v[0])
	}
	t.Log("Sign() Success")
}

type testRequest struct {
	Method string
	Signature string
}


func TestRequest(t *testing.T) {
	// each different method changes the signature
	methods := []testRequest{
		{"GET", "2RFMXrQACR5ceZOJtMxfu18+4pmNGniMfS/KqNLZuqU="},
		{"POST", "ZiTmmsnuM/8XfmZMHAeWrW9ADiEGCLh7t4e87VBbLr4="},
		{"PUT", "fEsTbzCLJgjryTf/gCPiGEGy+D8zCUSk5bGr6v2yJT4="},
		{"DELETE", "kOUd36K8bpUje2fzfgeyxt7OLNg5K+cGmN7YbKdpPD4="},
	}
	for _, method := range methods {
		// making a new map instead of global because it's modified
		params := url.Values{
			"Message":   {"Hi Test"},
			"TopicArn":  {"arn:aws:sns:us-east-1:123456789:example-message"},
			"Timestamp": {"2012-05-21T21:16:38Z"},
			"Version":   {"2010-03-31"},
			"Action":    {"Publish"},
		}
		res, err := Request(
			aws_key,
			aws_secret,
			method.Method,
			"my.verbalink.com",
			"/awssign.go/test",
			params,
		)
		if nil == res {
			t.Errorf(
				"Couldn't connect to ssl test site doing a %s, maybe use your own?: %s",
				method.Method,
				err,
			)
			return
		}
		if params.Get("Signature") != method.Signature {
			t.Errorf(
				"Expecting Signature from %s \"%s\" received \"%s\"",
				method.Method,
				method.Signature,
				params.Get("Signature"),
			)
		}
	}
}

