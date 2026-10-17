package crypto

import (
	"bytes"
	"errors"
	"math/big"
	"testing"
)

func testCSVSealingKey() []byte {
	key := make([]byte, CSVSealingKeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

func TestDeriveSealingKeyFromCSV_DeterministicAndLength(t *testing.T) {
	hwKey := testCSVSealingKey()

	first, err := DeriveSealingKeyFromCSV(hwKey)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	second, err := DeriveSealingKeyFromCSV(hwKey)
	if err != nil {
		t.Fatalf("derive again: %v", err)
	}

	if len(first) != 16 {
		t.Fatalf("expected a 16-byte key, got %d", len(first))
	}
	if !bytes.Equal(first, second) {
		t.Fatal("derivation is not deterministic")
	}
}

func TestDeriveSealingKeyFromCSV_MatchesDocumentedMaterial(t *testing.T) {
	hwKey := testCSVSealingKey()
	label := []byte("TAA-STATE-SEALING-CSV-V1")
	counter := []byte{0x00, 0x00, 0x00, 0x01}

	material := make([]byte, 0, len(hwKey)+len(label)+len(counter))
	material = append(material, hwKey...)
	material = append(material, label...)
	material = append(material, counter...)
	want := SM3Sum(material)

	got, err := DeriveSealingKeyFromCSV(hwKey)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if !bytes.Equal(got, want[:16]) {
		t.Fatalf("derived key does not match SM3(hwKey || label || counter)[:16]: got %x want %x", got, want[:16])
	}
}

func TestDeriveSealingKeyFromCSV_DomainSeparationFromLegacy(t *testing.T) {
	hwKey := testCSVSealingKey()
	legacy := DeriveSealingKey(&SM2PrivateKey{D: new(big.Int).SetBytes(hwKey)})

	got, err := DeriveSealingKeyFromCSV(hwKey)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if bytes.Equal(got, legacy) {
		t.Fatal("CSV derivation must not collide with the legacy SM2 derivation")
	}
}

func TestDeriveSealingKeyFromCSV_RejectsWrongLength(t *testing.T) {
	for _, size := range []int{0, 1, 16, 31, 33, 64} {
		if _, err := DeriveSealingKeyFromCSV(make([]byte, size)); !errors.Is(err, ErrInvalidCSVSealingKey) {
			t.Fatalf("size %d: expected ErrInvalidCSVSealingKey, got %v", size, err)
		}
	}
}

func TestDeriveSealingKeyFromCSV_RejectsAllZero(t *testing.T) {
	if _, err := DeriveSealingKeyFromCSV(make([]byte, CSVSealingKeySize)); !errors.Is(err, ErrInvalidCSVSealingKey) {
		t.Fatalf("expected ErrInvalidCSVSealingKey, got %v", err)
	}
}
