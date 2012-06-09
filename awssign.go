/*
	Copyright © 2012, Robert Wallis <robert-wallis@ieee.org>
	See LICENSE file for more information.
*/
package awssign

import (
	"net/url"
)

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
