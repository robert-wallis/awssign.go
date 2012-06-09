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

