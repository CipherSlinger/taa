package resource

import (
	"strings"
	"testing"
)

func TestSplitDeliveryParams(t *testing.T) {
	const (
		cipher = "04aabbcc"
		name   = "report%20final.zip"
		code   = "RES%2F001"
	)

	t.Run("all three parameters are stripped and their raw values returned", func(t *testing.T) {
		raw := "http://host/files/data.sm4?sign=a%2Fb&dataKeyCipher=" + cipher + "&fileName=" + name + "&dataResourceCode=" + code + "&expires=99"
		clean, values, err := SplitDeliveryParams(raw, "dataKeyCipher", "fileName", "dataResourceCode")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if clean != "http://host/files/data.sm4?sign=a%2Fb&expires=99" {
			t.Fatalf("clean = %q", clean)
		}
		if values["dataKeyCipher"] != cipher {
			t.Fatalf("dataKeyCipher = %q", values["dataKeyCipher"])
		}
		// Values are returned exactly as they appeared; decoding is the caller's job.
		if values["fileName"] != name {
			t.Fatalf("fileName = %q, want the raw %q", values["fileName"], name)
		}
		if values["dataResourceCode"] != code {
			t.Fatalf("dataResourceCode = %q, want the raw %q", values["dataResourceCode"], code)
		}
	})

	t.Run("question-mark separators from plain concatenation are accepted", func(t *testing.T) {
		// A producer appending each parameter with "?" to an already-signed link
		// must leave the signed part byte-for-byte intact.
		signed := "http://host/files/data.sm4?X-Amz-Signature=deadbeef"
		raw := signed + "?dataKeyCipher=" + cipher + "?fileName=" + name + "?dataResourceCode=" + code
		clean, values, err := SplitDeliveryParams(raw, "dataKeyCipher", "fileName", "dataResourceCode")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if clean != signed {
			t.Fatalf("clean = %q, want %q", clean, signed)
		}
		if len(values) != 3 {
			t.Fatalf("values = %v, want all three", values)
		}
	})

	t.Run("adjacent parameters do not corrupt the survivors", func(t *testing.T) {
		raw := "http://host/f?dataKeyCipher=" + cipher + "?fileName=" + name + "?dataResourceCode=" + code + "?keep=1"
		clean, _, err := SplitDeliveryParams(raw, "dataKeyCipher", "fileName", "dataResourceCode")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if clean != "http://host/f?keep=1" {
			t.Fatalf("clean = %q", clean)
		}
	})

	t.Run("a sole parameter drops the query mark", func(t *testing.T) {
		clean, values, err := SplitDeliveryParams("http://host/f?fileName="+name, "fileName")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if clean != "http://host/f" {
			t.Fatalf("clean = %q", clean)
		}
		if values["fileName"] != name {
			t.Fatalf("fileName = %q", values["fileName"])
		}
	})

	t.Run("the fragment is preserved", func(t *testing.T) {
		clean, _, err := SplitDeliveryParams("http://host/f?fileName="+name+"#part", "fileName")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if clean != "http://host/f#part" {
			t.Fatalf("clean = %q", clean)
		}
	})

	t.Run("absent names are omitted and the URL is untouched", func(t *testing.T) {
		raw := "http://host/f?a=1&b=2"
		clean, values, err := SplitDeliveryParams(raw, "fileName", "dataResourceCode")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if clean != raw {
			t.Fatalf("clean = %q, want %q", clean, raw)
		}
		if len(values) != 0 {
			t.Fatalf("values = %v, want empty", values)
		}
	})

	t.Run("no query string leaves the URL untouched", func(t *testing.T) {
		raw := "http://host/f"
		clean, alone, err := SplitDeliveryParams(raw, "fileName")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if clean != raw || len(alone) != 0 {
			t.Fatalf("clean = %q, values = %v", clean, alone)
		}
	})

	t.Run("duplicate parameters are rejected", func(t *testing.T) {
		_, _, err := SplitDeliveryParams("http://host/f?fileName=a&fileName=b", "fileName")
		if err == nil || !strings.Contains(err.Error(), "重复") {
			t.Fatalf("err = %v, want a duplicate error", err)
		}
	})

	t.Run("empty and valueless parameters are rejected", func(t *testing.T) {
		for _, raw := range []string{"http://host/f?fileName=", "http://host/f?fileName"} {
			if _, _, err := SplitDeliveryParams(raw, "fileName"); err == nil {
				t.Fatalf("%q accepted, want error", raw)
			}
		}
	})

	t.Run("names are case-sensitive", func(t *testing.T) {
		raw := "http://host/f?FileName=a"
		clean, values, err := SplitDeliveryParams(raw, "fileName")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if clean != raw || len(values) != 0 {
			t.Fatalf("clean = %q, values = %v", clean, values)
		}
	})
}
