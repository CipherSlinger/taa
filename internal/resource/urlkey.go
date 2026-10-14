package resource

import (
	"fmt"
	"strings"
)

// dataKeyCipherParam is the query parameter that carries the SM2 data key envelope
// on a data-delivery resource URL.
const dataKeyCipherParam = "dataKeyCipher"

// SplitDataKeyCipher strips the dataKeyCipher parameter from a resource URL and
// returns the downloadable URL together with the parameter's raw hex value.
//
// found is false when the URL carries no such parameter; the caller then falls
// back to the legacy format. Only two cases return an error: the parameter
// appears more than once (which one to use would be ambiguous), or its value is
// empty.
//
// On error all three results are zero: an erroring call never yields a URL to
// download from and never yields a hex value to unwrap. Callers must check err
// before consulting found.
//
// The strip is segment-by-segment string surgery: the bytes, order and escaping
// of every other query segment are preserved verbatim, so a signed download URL
// is never rewritten.
func SplitDataKeyCipher(rawURL string) (cleanURL, hexValue string, found bool, err error) {
	base, query, fragment := splitURLParts(rawURL)
	if query == "" {
		return rawURL, "", false, nil
	}

	segments := splitQuerySegments(query)
	foundAt := -1
	for i, seg := range segments {
		eq := strings.Index(seg.text, "=")
		key := seg.text
		if eq >= 0 {
			key = seg.text[:eq]
		}
		if key != dataKeyCipherParam {
			continue
		}
		if foundAt >= 0 {
			return "", "", false, fmt.Errorf("URL 中 %s 参数重复出现，无法判定使用哪一个", dataKeyCipherParam)
		}
		value := ""
		if eq >= 0 {
			value = seg.text[eq+1:]
		}
		if value == "" {
			return "", "", false, fmt.Errorf("URL 中 %s 参数值为空", dataKeyCipherParam)
		}
		foundAt = i
		hexValue = value
	}
	if foundAt < 0 {
		return rawURL, "", false, nil
	}

	// Cut the parameter out together with one adjacent delimiter, so what is left is
	// exactly the URL that would have been sent without it. Which delimiter depends
	// on where the parameter sits: the first segment lends the '?' that opens the
	// query to the segment after it, any later segment takes the '&' (or the stray
	// '?') in front of it.
	target := segments[foundAt]
	var cleanQuery string
	switch {
	case foundAt == 0 && len(segments) == 1:
		cleanQuery = ""
	case foundAt == 0:
		cleanQuery = query[segments[1].start:]
	default:
		cleanQuery = query[:target.start-1] + query[target.start+len(target.text):]
	}

	clean := base
	if cleanQuery != "" {
		clean += "?" + cleanQuery
	}
	return clean + fragment, hexValue, true, nil
}

// querySegment is one key=value chunk of a URL query: its text, where it starts in
// the query, and the delimiter that introduces it.
type querySegment struct {
	text  string
	start int
}

// splitQuerySegments cuts a query string at every '&' and every '?'.
//
// '?' is a delimiter here and not merely the character that opens the query,
// because a producer that appends the envelope by plain concatenation
// (url + "?dataKeyCipher=") to a link that already carries a query string produces
// "...&X-Amz-Signature=<hex>?dataKeyCipher=<hex>" -- and presigned links always
// carry one. Reading the stray '?' as a segment delimiter finds the envelope and
// restores the URL byte-for-byte; reading it as part of the signature's value would
// leave the parameter undetected and the download rejected as badly signed.
func splitQuerySegments(query string) []querySegment {
	segments := make([]querySegment, 0, 4)
	start := 0
	for i := 0; i <= len(query); i++ {
		if i < len(query) && query[i] != '&' && query[i] != '?' {
			continue
		}
		segments = append(segments, querySegment{text: query[start:i], start: start})
		start = i + 1
	}
	return segments
}

// splitURLParts cuts a URL into base, query and fragment (the fragment keeps its
// leading '#'). An empty query means the URL has no query part.
func splitURLParts(rawURL string) (base, query, fragment string) {
	rest := rawURL
	if i := strings.Index(rest, "#"); i >= 0 {
		fragment = rest[i:]
		rest = rest[:i]
	}
	if i := strings.Index(rest, "?"); i >= 0 {
		return rest[:i], rest[i+1:], fragment
	}
	return rest, "", fragment
}
