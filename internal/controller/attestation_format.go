package controller

import (
	"encoding/json"
	"fmt"
	"math/big"

	teecrypto "taa/crypto"
	"taa/internal/attestation"
)

func formatAttestationValuesUserDataPEM(reportValues string, userData []byte) (string, error) {
	if len(userData) != attestation.UserDataSize {
		return "", fmt.Errorf("userdata must be %d bytes, got %d", attestation.UserDataSize, len(userData))
	}

	var values attestation.ReportValues
	if err := json.Unmarshal([]byte(reportValues), &values); err != nil {
		return "", fmt.Errorf("unmarshal attestation values: %w", err)
	}

	pub := &teecrypto.SM2PublicKey{
		X: new(big.Int).SetBytes(userData[:32]),
		Y: new(big.Int).SetBytes(userData[32:]),
	}
	pemBytes, err := teecrypto.MarshalSM2PublicKeyPEM(pub)
	if err != nil {
		return "", fmt.Errorf("marshal userdata to PEM: %w", err)
	}

	values.UserData = string(pemBytes)
	formatted, err := json.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("marshal attestation values: %w", err)
	}
	return string(formatted), nil
}
