package awssign

import (
	"testing"
)

func TestAwsSign(t *testing.T) {
	//  http://sns.us-east-1.amazonaws.com/
	//  ?Subject=My%20first%20message
	//  &TopicArn=arn%3Aaws%3Asns%3Aus-east-1%3A698519295917%3AMy-Topic
	//  &Message=Hello%20world%21
	//  &Action=Publish
	//  &SignatureVersion=2
	//  &SignatureMethod=HmacSHA256
	//  &Timestamp=2010-03-31T12%3A00%3A00.000Z
	//  &AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE
	//  &Signature=9GZysQ4Jpnz%2BHklqM7VFTvEcjR2LIUtn6jW47054xxE%3D
	creds := AwsCredentials{"AKIAIOSFODNN7EXAMPLE", "EXAMPLE+SECRET"}
	params := map[string]string{
		"Subject": "My first message",
		"TopicArn": "arn:aws:sns:us-east-1:698519295917:My-Topic",
		"Message": "Hello world%21",
		"Action": "Publish",
		"Timestamp": "2010-03-31T12:00:00.000Z",
		"AWSAccessKeyId": "AKIAIOSFODNN7EXAMPLE",
	};
	AwsSign(creds, "GET", "sns.us-east-1.amazonaws.com", "/", params)

	if v, ok := params["SignatureVersion"]; !ok || "2" != v {
		t.Fatalf("SignatureVersion expecting %s got %s", "2", v)
	}
	if v, ok := params["SignatureMethod"]; !ok || "HmacSHA256" != v {
		t.Fatalf("SignatureMethod expecting %s got %s", "HmacSHA256", v)
	}
	signature := "jUkpstt7U+ENbD++Ou9usiKHh61dLFi4lVZTHqzO8as="
	if v, ok := params["Signature"]; !ok || signature != v {
		t.Fatalf("Sigunature expecting %s got %s", signature, v)
	}
}
