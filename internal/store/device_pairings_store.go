package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/onebusaway/hooks/internal/store/sqlcgen"
)

func devicePairingFromGen(r sqlcgen.DevicePairing) (DevicePairing, error) {
	dp := DevicePairing{
		DeviceCode:          r.DeviceCode,
		UserCode:            r.UserCode,
		Status:              DevicePairingStatus(r.Status),
		CreatedAt:           time.Unix(0, r.CreatedAt).UTC(),
		ExpiresAt:           time.Unix(0, r.ExpiresAt).UTC(),
		UserID:              ptrFromNullString(r.UserID),
		RequestingIP:        r.RequestingIp,
		RequestingUserAgent: r.RequestingUserAgent,
		PlaintextToken:      ptrFromNullString(r.PlaintextToken),
		TokenID:             ptrFromNullString(r.TokenID),
	}
	scopes := strings.TrimSpace(r.RequestedScopes)
	if scopes == "" {
		dp.RequestedScopes = []string{}
	} else if err := json.Unmarshal([]byte(scopes), &dp.RequestedScopes); err != nil {
		return DevicePairing{}, err
	}
	if dp.RequestedScopes == nil {
		dp.RequestedScopes = []string{}
	}
	return dp, nil
}

func (s *SQLite) InsertDevicePairing(ctx context.Context, dp DevicePairing) error {
	if dp.DeviceCode == "" || dp.UserCode == "" {
		return errors.New("InsertDevicePairing: empty device_code or user_code")
	}
	scopes, err := json.Marshal(scopesOrEmpty(dp.RequestedScopes))
	if err != nil {
		return err
	}
	if dp.Status == "" {
		dp.Status = DevicePairingStatusPending
	}
	return s.q.InsertDevicePairing(ctx, sqlcgen.InsertDevicePairingParams{
		DeviceCode:          dp.DeviceCode,
		UserCode:            dp.UserCode,
		Status:              string(dp.Status),
		CreatedAt:           dp.CreatedAt.UTC().UnixNano(),
		ExpiresAt:           dp.ExpiresAt.UTC().UnixNano(),
		UserID:              nullStringPtr(dp.UserID),
		RequestingIp:        dp.RequestingIP,
		RequestingUserAgent: dp.RequestingUserAgent,
		RequestedScopes:     string(scopes),
		PlaintextToken:      nullStringPtr(dp.PlaintextToken),
		TokenID:             nullStringPtr(dp.TokenID),
	})
}

func (s *SQLite) GetDevicePairingByDeviceCode(ctx context.Context, deviceCode string) (DevicePairing, error) {
	row, err := s.q.GetDevicePairingByDeviceCode(ctx, deviceCode)
	if errors.Is(err, sql.ErrNoRows) {
		return DevicePairing{}, ErrNotFound
	}
	if err != nil {
		return DevicePairing{}, err
	}
	return devicePairingFromGen(row)
}

func (s *SQLite) GetDevicePairingByUserCode(ctx context.Context, userCode string) (DevicePairing, error) {
	row, err := s.q.GetDevicePairingByUserCode(ctx, userCode)
	if errors.Is(err, sql.ErrNoRows) {
		return DevicePairing{}, ErrNotFound
	}
	if err != nil {
		return DevicePairing{}, err
	}
	return devicePairingFromGen(row)
}

// ApproveDevicePairing transitions a pending row to approved_unfetched within
// a transaction, also inserting the freshly minted PAT row into
// listener_tokens. Returns ErrNotFound if the user_code does not refer to a
// pending pairing.
func (s *SQLite) ApproveDevicePairing(ctx context.Context, userCode string, tok Token, plaintextToken string, approverUserID string, when time.Time) error {
	if userCode == "" || tok.ID == "" {
		return errors.New("ApproveDevicePairing: empty user_code or token id")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	q := s.q.WithTx(tx)

	// Insert the PAT row first so the FK reference from device_pairings.token_id
	// is valid.
	scopes := strings.Join(tok.Scopes, ",")
	kind := string(tok.Kind)
	if kind == "" {
		kind = string(TokenKindPAT)
	}
	eph := int64(0)
	if tok.Ephemeral {
		eph = 1
	}
	if err := q.InsertToken(ctx, sqlcgen.InsertTokenParams{
		ID:          tok.ID,
		Name:        tok.Name,
		Scopes:      scopes,
		SecretHash:  tok.SecretHash,
		CreatedAt:   when.UTC().UnixNano(),
		OwnerUserID: sql.NullString{String: approverUserID, Valid: true},
		Kind:        kind,
		Ephemeral:   eph,
		ExpiresAt:   nullInt64FromTime(tok.ExpiresAt),
	}); err != nil {
		return err
	}

	n, err := q.UpdateDevicePairingApproved(ctx, sqlcgen.UpdateDevicePairingApprovedParams{
		UserID:         sql.NullString{String: approverUserID, Valid: true},
		PlaintextToken: sql.NullString{String: plaintextToken, Valid: true},
		TokenID:        sql.NullString{String: tok.ID, Valid: true},
		UserCode:       userCode,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

func (s *SQLite) DenyDevicePairing(ctx context.Context, userCode, byUser string) error {
	n, err := s.q.UpdateDevicePairingDenied(ctx, sqlcgen.UpdateDevicePairingDeniedParams{
		UserID:   sql.NullString{String: byUser, Valid: true},
		UserCode: userCode,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) MarkDevicePairingFetched(ctx context.Context, deviceCode string) error {
	n, err := s.q.MarkDevicePairingFetched(ctx, deviceCode)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) ExpirePendingDevicePairings(ctx context.Context, before time.Time) (int64, error) {
	return s.q.ExpirePendingDevicePairings(ctx, before.UTC().UnixNano())
}

func (s *SQLite) DeleteOldDevicePairings(ctx context.Context, before time.Time) (int64, error) {
	return s.q.DeleteOldDevicePairings(ctx, before.UTC().UnixNano())
}
