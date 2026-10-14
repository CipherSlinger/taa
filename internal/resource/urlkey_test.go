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
