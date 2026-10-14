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

	segments := strings.Split(query, "&")
	kept := make([]string, 0, len(segments))
	for _, seg := range segments {
		eq := strings.Index(seg, "=")
		key := seg
		if eq >= 0 {
			key = seg[:eq]
		}
		if key != dataKeyCipherParam {
			kept = append(kept, seg)
			continue
		}
		if found {
			return "", "", false, fmt.Errorf("URL 中 %s 参数重复出现，无法判定使用哪一个", dataKeyCipherParam)
		}
		value := ""
		if eq >= 0 {
			value = seg[eq+1:]
		}
		if value == "" {
			return "", "", false, fmt.Errorf("URL 中 %s 参数值为空", dataKeyCipherParam)
		}
		found = true
		hexValue = value
	}
	if !found {
		return rawURL, "", false, nil
	}

	clean := base
	if len(kept) > 0 {
		clean += "?" + strings.Join(kept, "&")
	}
	return clean + fragment, hexValue, true, nil
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
