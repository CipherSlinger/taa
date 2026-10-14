package resource

import (
	"strings"
	"testing"
)

func TestSplitDataKeyCipher(t *testing.T) {
	const hexValue = "04aabbcc"

	t.Run("no query string leaves the URL untouched", func(t *testing.T) {
		raw := "http://host/files/data.sm4"
		clean, hex, found, err := SplitDataKeyCipher(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found {
			t.Fatalf("found = true, want false")
		}
		if clean != raw {
			t.Fatalf("clean = %q, want %q", clean, raw)
		}
		if hex != "" {
			t.Fatalf("hex = %q, want empty", hex)
		}
	})

	t.Run("sole parameter is stripped and the query mark is dropped", func(t *testing.T) {
		clean, hex, found, err := SplitDataKeyCipher("http://host/files/data.sm4?dataKeyCipher=" + hexValue)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !found || hex != hexValue {
			t.Fatalf("found=%v hex=%q, want true/%q", found, hex, hexValue)
		}
		if clean != "http://host/files/data.sm4" {
			t.Fatalf("clean = %q", clean)
		}
	})

	t.Run("other parameters keep their order and escaping", func(t *testing.T) {
		raw := "http://host/files/data.sm4?sign=a%2Fb&dataKeyCipher=" + hexValue + "&expires=99"
		clean, hex, found, err := SplitDataKeyCipher(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !found || hex != hexValue {
			t.Fatalf("found=%v hex=%q", found, hex)
		}
		want := "http://host/files/data.sm4?sign=a%2Fb&expires=99"
		if clean != want {
			t.Fatalf("clean = %q, want %q", clean, want)
		}
	})

	t.Run("fragment is preserved", func(t *testing.T) {
		clean, _, found, err := SplitDataKeyCipher("http://host/f.sm4?dataKeyCipher=" + hexValue + "#part")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !found || clean != "http://host/f.sm4#part" {
			t.Fatalf("found=%v clean=%q", found, clean)
		}
	})

	t.Run("a parameter whose value merely contains the name is left alone", func(t *testing.T) {
		raw := "http://host/f.sm4?sign=dataKeyCipher"
		clean, _, found, err := SplitDataKeyCipher(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found || clean != raw {
			t.Fatalf("found=%v clean=%q, want false/%q", found, clean, raw)
		}
	})

	t.Run("an envelope appended with a stray question mark is still stripped", func(t *testing.T) {
		// What plain concatenation produces on a presigned link: the producer appends
		// "?dataKeyCipher=" to a URL that already has a query string, so the delimiter
		// inside the query is a '?' and the parameter would otherwise be read as part
		// of the signature's value.
		signed := "http://host/files/data.sm4?X-Amz-Signature=6092f943d67c3bd99f00accfa330c7fd92a7293db2551c5525b55909a5cbca37"
		clean, hex, found, err := SplitDataKeyCipher(signed + "?dataKeyCipher=" + hexValue)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !found || hex != hexValue {
			t.Fatalf("found=%v hex=%q, want true/%q", found, hex, hexValue)
		}
		if clean != signed {
			t.Fatalf("clean = %q, want the signed URL byte-for-byte (%q)", clean, signed)
		}
	})

	t.Run("a stray question mark in the middle keeps the rest of the query", func(t *testing.T) {
		raw := "http://host/f.sm4?a=1?dataKeyCipher=" + hexValue + "&b=2"
		clean, _, found, err := SplitDataKeyCipher(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !found || clean != "http://host/f.sm4?a=1&b=2" {
			t.Fatalf("found=%v clean=%q", found, clean)
		}
	})

	t.Run("a stray question mark in front of the fragment keeps the fragment", func(t *testing.T) {
		raw := "http://host/f.sm4?a=1?dataKeyCipher=" + hexValue + "#part"
		clean, _, found, err := SplitDataKeyCipher(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !found || clean != "http://host/f.sm4?a=1#part" {
			t.Fatalf("found=%v clean=%q", found, clean)
		}
	})

	t.Run("duplicate parameter is rejected", func(t *testing.T) {
		_, _, _, err := SplitDataKeyCipher("http://host/f.sm4?dataKeyCipher=aa&dataKeyCipher=bb")
		if err == nil {
			t.Fatal("expected error for duplicate parameter")
		}
		if !strings.Contains(err.Error(), "重复") {
			t.Fatalf("err = %v, want it to mention 重复", err)
		}
	})

	t.Run("empty value is rejected", func(t *testing.T) {
		_, _, _, err := SplitDataKeyCipher("http://host/f.sm4?dataKeyCipher=")
		if err == nil {
			t.Fatal("expected error for empty value")
		}
		if !strings.Contains(err.Error(), "值为空") {
			t.Fatalf("err = %v, want it to mention 为空", err)
		}
	})

	t.Run("a parameter with no equals sign is rejected as empty", func(t *testing.T) {
		_, _, _, err := SplitDataKeyCipher("http://host/f.sm4?dataKeyCipher")
		if err == nil {
			t.Fatal("expected error for a valueless parameter")
		}
		if !strings.Contains(err.Error(), "值为空") {
			t.Fatalf("err = %v, want it to mention 为空", err)
		}
	})
}
