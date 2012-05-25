# Purpose
Some AWS libraries try to do everything for each service,
but Amazon is so diverse with many services, and they add and update
their services constantly.

We are developers, we can easily read the Amazon docs on what params to use.

All I wanted is something to do the hard part, sign a request. (and maybe send it)

# Installation
After installing go:
http://code.google.com/p/go/downloads/list

```
go get github.com/verbalink/go-awssign
```

# Examples

## Example: Simple Notification Service
```go
package main

import "github.com/verbalink/go-awssign"

func main() {
	// this is a map of []strings because a key can have
	// multiple params, and it's of the type url.Values
	params := map[string][]string{
		"Message":  {"Is your refrigerator running?"},
		"TopicArn": {"arn:aws:sns:us-east-1:1111111111111111111:prank-txt"},
		"Action":   {"Publish"},
	}
    res, err := awssign.Request(
		aws_key,
		aws_secret,
		"GET",
		"sns.us-east-1.amazonaws.com",
		"/",
		params,
	)
	// request sent!
	// do whatever you want with res
	// res is an *http.Response type
}
```

## Example: if you wanted to do your own request
```go
params := url.Values{
	"Message":  {"Is your refrigerator running?"},
	"TopicArn": {"arn:aws:sns:us-east-1:1111111111111111111:prank-txt"},
	"Action":   {"Publish"},
}
a := awssign.AwsSign{
	aws_key,
	aws_secret,
	"GET",
	"sns.us-east-1.amazonaws.com",
	"/",
	params,
}
// do the actual sign
a.Sign()

// do whatever you want with params, they are setup to be used
fmt.Println(params.Encode())
```

