package store

import (
	"testing"
)

func TestDevicePairing_ApprovedToken(t *testing.T) {
	plaintext := "secret-plaintext"
	tokenID := "tok_abc"

	tests := []struct {
		name        string
		pairing     DevicePairing
		wantOK      bool
		wantPT      string
		wantTokenID string
	}{
		{
			name: "approved with both fields populated returns ok",
			pairing: DevicePairing{
				Status:         DevicePairingStatusApprovedUnfetched,
				PlaintextToken: &plaintext,
				TokenID:        &tokenID,
			},
			wantOK:      true,
			wantPT:      plaintext,
			wantTokenID: tokenID,
		},
		{
			name: "approved but missing plaintext returns not ok",
			pairing: DevicePairing{
				Status:         DevicePairingStatusApprovedUnfetched,
				PlaintextToken: nil,
				TokenID:        &tokenID,
			},
			wantOK: false,
		},
		{
			name: "approved but missing token id returns not ok",
			pairing: DevicePairing{
				Status:         DevicePairingStatusApprovedUnfetched,
				PlaintextToken: &plaintext,
				TokenID:        nil,
			},
			wantOK: false,
		},
		{
			name: "pending status never returns ok",
			pairing: DevicePairing{
				Status:         DevicePairingStatusPending,
				PlaintextToken: &plaintext,
				TokenID:        &tokenID,
			},
			wantOK: false,
		},
		{
			name: "done status never returns ok",
			pairing: DevicePairing{
				Status:         DevicePairingStatusDone,
				PlaintextToken: &plaintext,
				TokenID:        &tokenID,
			},
			wantOK: false,
		},
		{
			name: "denied status never returns ok",
			pairing: DevicePairing{
				Status:         DevicePairingStatusDenied,
				PlaintextToken: &plaintext,
				TokenID:        &tokenID,
			},
			wantOK: false,
		},
		{
			name: "expired status never returns ok",
			pairing: DevicePairing{
				Status:         DevicePairingStatusExpired,
				PlaintextToken: &plaintext,
				TokenID:        &tokenID,
			},
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotPT, gotTokenID, gotOK := tc.pairing.ApprovedToken()
			if gotOK != tc.wantOK {
				t.Fatalf("ApprovedToken() ok = %v, want %v", gotOK, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if gotPT != tc.wantPT {
				t.Errorf("plaintext = %q, want %q", gotPT, tc.wantPT)
			}
			if gotTokenID != tc.wantTokenID {
				t.Errorf("tokenID = %q, want %q", gotTokenID, tc.wantTokenID)
			}
		})
	}
}
