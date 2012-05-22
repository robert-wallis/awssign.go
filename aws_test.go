package awssign

import (
	"testing"
)

func TestAwsSign(t *testing.T) {
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
	params := map[string]string{
		"Message":     "Hi Test",
		"TopicArn":    "arn:aws:sns:us-east-1:123456789:example-message",
		"Timestamp":   "2012-05-21T21:16:38Z",
		"Version":     "2010-03-31",
		"Action":      "Publish",
		"ContentType": "JSON",
	}
	params = AwsSign("EXAMPLE+AWS+KEY", "EXAMPLE+AWS+SECRET", "GET", "sns.us-east-1.amazonaws.com", "/", params)

	// verify it worked
	if v, ok := params["SignatureVersion"]; !ok || "2" != v {
		t.Fatalf("SignatureVersion expecting %s got %s", "2", v)
	}
	if v, ok := params["SignatureMethod"]; !ok || "HmacSHA256" != v {
		t.Fatalf("SignatureMethod expecting %s got %s", "HmacSHA256", v)
	}
	signature := "NU/UNneSfY3qMk78Wetdp+7xGyM2uelG+nsr17OEzSU="
	if v, ok := params["Signature"]; !ok || signature != v {
		t.Fatalf("Sigunature expecting %s got %s", signature, v)
	}
}
