/*
	Copyright © 2012, Robert Wallis <robert-wallis@ieee.org>
	See LICENSE file for more information.
*/
package awssign

// modified from net.url because shouldEscape is
// overriden with an encodeQueryComponent 'if'
// http://golang.org/src/pkg/net/url/url.go?s=4017:4682#L175
func escape(s string) string {
	spaceCount, hexCount := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if shouldEscape(c) {
			hexCount++
		}
	}

	if spaceCount == 0 && hexCount == 0 {
		return s
	}

	t := make([]byte, len(s)+2*hexCount)
	j := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case shouldEscape(c):
			t[j] = '%'
			t[j+1] = "0123456789ABCDEF"[c>>4]
			t[j+2] = "0123456789ABCDEF"[c&15]
			j += 3
		default:
			t[j] = s[i]
			j++
		}
	}
	return string(t)
}

// truncated from pkg net/url
// according to RFC 3986
func shouldEscape(c byte) bool {
	switch {
	// §2.3 Unreserved characters (alphanum)
	case 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9':
		return false
	// §2.3 Unreserved characters (mark)
	case '-' == c, '_' == c, '.' == c, '~' == c:
		return false
	}
	return true
}
