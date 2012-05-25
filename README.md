# Installation
After installing go:
http://code.google.com/p/go/downloads/list

```
go get github.com/robert-wallis/go-awssign
```

# Examples

## Example: Simple Notification Service
```go
package main

import "github.com/robert-wallis/go-awssign"

func main() {
	var res *http.Response
	var err error
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

