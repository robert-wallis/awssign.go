/*
	Copyright © 2012, Robert Wallis <robert-wallis@ieee.org>
	See LICENSE file for more information.
*/
package awssign

import (
	"net/url"
	"testing"
)

func TestCanonicalQueryString(t *testing.T) {
	params := url.Values{
		"Date": {"Mon, 09 Sep 2011 23:36:00 GMT"},
		"Host": {"host.foo.com"},
	}
	a := AwsSignatureV4{
		HttpMethod: "GET",
		Params:     params,
		Uri:        "/",
	}

	answer := "GET\n/\n\ndate:Mon, 09 Sep 2011 23:36:00 GMT\nhost:host.foo.com\n\ndate;host\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	guess := a.canonicalRequest()
	if answer != guess {
		t.Errorf(
			"Expecting %s from canonicalRequest() received \"%s\"",
			answer,
			guess,
		)
	}
}
