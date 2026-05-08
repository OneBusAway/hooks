package store

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"database/sql"

	"github.com/onebusaway/hooks/internal/store/sqlcgen"
	_ "modernc.org/sqlite"
)

// SQLite is the default backend. It implements EventStore, TokenStore,
// PushSubscriptionStore, UserStore, SessionStore, InviteStore,
// DevicePairingStore, and AuditStore by delegating to the sqlc-generated
// *sqlcgen.Queries. The wrapper layer is the single conversion point between
// SQL-native types (sql.NullInt64, sql.NullString, int64 unix-nano) and the
// public types' time.Time / []string / *time.Time shapes.
type SQLite struct {
	db           *sql.DB
	q            *sqlcgen.Queries
	dedupeWindow time.Duration
	tokenHash    HashLookup
}

// SQLiteOptions configures a SQLite store.
type SQLiteOptions struct {
	// DedupeWindow controls how far back the (source, delivery_id) check
	// considers a row a duplicate.
	DedupeWindow time.Duration
}

//go:embed schema.sql
var schemaSQL string

// OpenSQLite opens (and migrates) a SQLite database at dsn.
func OpenSQLite(dsn string, opts SQLiteOptions) (*SQLite, error) {
	if opts.DedupeWindow == 0 {
		opts.DedupeWindow = 24 * time.Hour
	}

	db, err := sql.Open("sqlite", normalizeDSN(dsn))
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)

	pragmas := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA foreign_keys=ON;",
		"PRAGMA busy_timeout=5000;",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("pragma %q: %w", p, err)
		}
	}

	s := &SQLite{
		db:           db,
		q:            sqlcgen.New(db),
		dedupeWindow: opts.DedupeWindow,
	}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func normalizeDSN(in string) string {
	if strings.HasPrefix(in, "sqlite:") {
		return strings.TrimPrefix(in, "sqlite:")
	}
	if strings.HasPrefix(in, "file:") {
		return in
	}
	return "file:" + url.PathEscape(in) + "?cache=shared"
}

func (s *SQLite) Close() error { return s.db.Close() }

func (s *SQLite) Ping(ctx context.Context) error {
	row := s.db.QueryRowContext(ctx, "SELECT 1")
	var n int
	return row.Scan(&n)
}

func (s *SQLite) migrate(ctx context.Context) error {
	// Apply ALTER deltas first: on an existing v1 database this adds the new
	// columns to listener_tokens / push_subscriptions BEFORE schema.sql tries
	// to CREATE INDEX on those columns. On a fresh DB the deltas are no-ops
	// because the target tables don't exist yet (they will be created by
	// schema.sql below with the new columns already in place).
	if err := applyMigrations(ctx, s.db); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, schemaSQL); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	return nil
}

// --- helpers -----------------------------------------------------------------

func nullInt64FromTime(t *time.Time) sql.NullInt64 {
	if t == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: t.UTC().UnixNano(), Valid: true}
}

func nullInt64FromUnix(t time.Time) sql.NullInt64 {
	return sql.NullInt64{Int64: t.UTC().UnixNano(), Valid: true}
}

func timePtrFromNullInt64(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := time.Unix(0, v.Int64).UTC()
	return &t
}

func nullStringPtr(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}

func nullStringFrom(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func ptrFromNullString(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	return &v.String
}

// --- EventStore --------------------------------------------------------------

func (s *SQLite) Append(ctx context.Context, in AppendInput) (Event, error) {
	if in.Source == "" {
		return Event{}, errors.New("Append: empty source")
	}
	if in.DeliveryID == "" {
		return Event{}, errors.New("Append: empty delivery_id")
	}

	headersJSON, err := json.Marshal(in.Headers)
	if err != nil {
		return Event{}, fmt.Errorf("marshal headers: %w", err)
	}
	sum := sha256.Sum256(in.Body)
	bodyHex := hex.EncodeToString(sum[:])
	receivedAt := time.Now().UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Event{}, err
	}
	defer func() { _ = tx.Rollback() }()
	q := s.q.WithTx(tx)

	cutoff := receivedAt.Add(-s.dedupeWindow).UnixNano()
	_, err = q.CheckEventDuplicate(ctx, sqlcgen.CheckEventDuplicateParams{
		Source:     in.Source,
		DeliveryID: in.DeliveryID,
		ReceivedAt: cutoff,
	})
	switch {
	case err == nil:
		return Event{}, ErrDuplicate
	case errors.Is(err, sql.ErrNoRows):
		// fall through
	default:
		return Event{}, err
	}

	nextSeq, err := q.NextEventSequence(ctx, in.Source)
	if err != nil {
		return Event{}, fmt.Errorf("next sequence: %w", err)
	}

	if err := q.InsertEvent(ctx, sqlcgen.InsertEventParams{
		Source:            in.Source,
		Sequence:          nextSeq,
		DeliveryID:        in.DeliveryID,
		ProviderTimestamp: in.ProviderTimestamp.UTC().UnixNano(),
		ReceivedAt:        receivedAt.UnixNano(),
		HeadersJson:       string(headersJSON),
		Body:              in.Body,
		BodySha256:        bodyHex,
	}); err != nil {
		return Event{}, fmt.Errorf("insert event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return Event{}, err
	}

	return Event{
		Source:            in.Source,
		Sequence:          nextSeq,
		DeliveryID:        in.DeliveryID,
		ProviderTimestamp: in.ProviderTimestamp.UTC(),
		ReceivedAt:        receivedAt,
		Headers:           cloneHeaders(in.Headers),
		Body:              in.Body,
		BodySHA256:        bodyHex,
	}, nil
}

func (s *SQLite) ReadSince(ctx context.Context, source string, cursor int64, limit int) ([]Event, error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := s.q.ReadEventsSince(ctx, sqlcgen.ReadEventsSinceParams{
		Source:   source,
		Sequence: cursor,
		Limit:    int64(limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]Event, 0, len(rows))
	for _, r := range rows {
		ev, err := eventFromGen(r)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, nil
}

func (s *SQLite) Get(ctx context.Context, source string, sequence int64) (Event, error) {
	row, err := s.q.GetEvent(ctx, sqlcgen.GetEventParams{Source: source, Sequence: sequence})
	if errors.Is(err, sql.ErrNoRows) {
		return Event{}, ErrNotFound
	}
	if err != nil {
		return Event{}, err
	}
	return eventFromGen(row)
}

func (s *SQLite) LatestSequence(ctx context.Context, source string) (int64, error) {
	return s.q.LatestEventSequence(ctx, source)
}

func (s *SQLite) Prune(ctx context.Context, source string, cutoff time.Time) (int64, error) {
	return s.q.PruneEventsBySource(ctx, sqlcgen.PruneEventsBySourceParams{
		Source:     source,
		ReceivedAt: cutoff.UTC().UnixNano(),
	})
}

func (s *SQLite) PruneAll(ctx context.Context, cutoff time.Time) (int64, error) {
	return s.q.PruneAllEvents(ctx, cutoff.UTC().UnixNano())
}

func (s *SQLite) Sources(ctx context.Context) ([]string, error) {
	return s.q.ListEventSources(ctx)
}

func eventFromGen(r sqlcgen.Event) (Event, error) {
	ev := Event{
		Source:            r.Source,
		Sequence:          r.Sequence,
		DeliveryID:        r.DeliveryID,
		ProviderTimestamp: time.Unix(0, r.ProviderTimestamp).UTC(),
		ReceivedAt:        time.Unix(0, r.ReceivedAt).UTC(),
		Body:              r.Body,
		BodySHA256:        r.BodySha256,
	}
	if err := json.Unmarshal([]byte(r.HeadersJson), &ev.Headers); err != nil {
		return Event{}, fmt.Errorf("decode headers: %w", err)
	}
	return ev, nil
}

// --- TokenStore --------------------------------------------------------------

// HashLookup is the hash function used by LookupByPlaintext to recompute the
// per-row hash for constant-time comparison. It is set by the tokens package
// at process start so the store package doesn't depend on argon2.
type HashLookup func(plaintext, encoded string) (bool, error)

// SetTokenHashCompare wires a verifier function for LookupByPlaintext.
func (s *SQLite) SetTokenHashCompare(fn HashLookup) {
	s.tokenHash = fn
}

func tokenFromGen(r sqlcgen.ListenerToken) Token {
	t := Token{
		ID:         r.ID,
		Name:       r.Name,
		Scopes:     splitScopes(r.Scopes),
		SecretHash: r.SecretHash,
		CreatedAt:  time.Unix(0, r.CreatedAt).UTC(),
		LastUsedAt: timePtrFromNullInt64(r.LastUsedAt),
		RevokedAt:  timePtrFromNullInt64(r.RevokedAt),
		OwnerUserID: ptrFromNullString(r.OwnerUserID),
		Kind:        TokenKind(r.Kind),
		Ephemeral:   r.Ephemeral != 0,
		ExpiresAt:   timePtrFromNullInt64(r.ExpiresAt),
	}
	return t
}

func (s *SQLite) Insert(ctx context.Context, t Token) error {
	scopes := strings.Join(t.Scopes, ",")
	kind := string(t.Kind)
	if kind == "" {
		kind = string(TokenKindListener)
	}
	eph := int64(0)
	if t.Ephemeral {
		eph = 1
	}
	return s.q.InsertToken(ctx, sqlcgen.InsertTokenParams{
		ID:          t.ID,
		Name:        t.Name,
		Scopes:      scopes,
		SecretHash:  t.SecretHash,
		CreatedAt:   t.CreatedAt.UTC().UnixNano(),
		OwnerUserID: nullStringPtr(t.OwnerUserID),
		Kind:        kind,
		Ephemeral:   eph,
		ExpiresAt:   nullInt64FromTime(t.ExpiresAt),
	})
}

func (s *SQLite) LookupByPlaintext(ctx context.Context, plaintext string) (Token, error) {
	if s.tokenHash == nil {
		return Token{}, ErrNotFound
	}
	rows, err := s.q.ListActiveTokens(ctx)
	if err != nil {
		return Token{}, err
	}
	for _, r := range rows {
		ok, err := s.tokenHash(plaintext, r.SecretHash)
		if err != nil {
			continue
		}
		if ok {
			return tokenFromGen(r), nil
		}
	}
	return Token{}, ErrNotFound
}

func (s *SQLite) TouchLastUsed(ctx context.Context, id string, when time.Time) error {
	return s.q.TouchTokenLastUsed(ctx, sqlcgen.TouchTokenLastUsedParams{
		LastUsedAt: nullInt64FromUnix(when),
		ID:         id,
	})
}

func (s *SQLite) List(ctx context.Context, includeRevoked bool) ([]Token, error) {
	flag := int64(0)
	if includeRevoked {
		flag = 1
	}
	rows, err := s.q.ListTokens(ctx, flag)
	if err != nil {
		return nil, err
	}
	out := make([]Token, 0, len(rows))
	for _, r := range rows {
		out = append(out, tokenFromGen(r))
	}
	return out, nil
}

func (s *SQLite) ListTokensByOwner(ctx context.Context, ownerUserID string, includeRevoked bool) ([]Token, error) {
	flag := int64(0)
	if includeRevoked {
		flag = 1
	}
	rows, err := s.q.ListTokensByOwner(ctx, sqlcgen.ListTokensByOwnerParams{
		OwnerUserID:    sql.NullString{String: ownerUserID, Valid: true},
		IncludeRevoked: flag,
	})
	if err != nil {
		return nil, err
	}
	out := make([]Token, 0, len(rows))
	for _, r := range rows {
		out = append(out, tokenFromGen(r))
	}
	return out, nil
}

func (s *SQLite) ListSystemTokens(ctx context.Context, includeRevoked bool) ([]Token, error) {
	flag := int64(0)
	if includeRevoked {
		flag = 1
	}
	rows, err := s.q.ListSystemTokens(ctx, flag)
	if err != nil {
		return nil, err
	}
	out := make([]Token, 0, len(rows))
	for _, r := range rows {
		out = append(out, tokenFromGen(r))
	}
	return out, nil
}

func (s *SQLite) GetToken(ctx context.Context, id string) (Token, error) {
	row, err := s.q.GetToken(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, ErrNotFound
	}
	if err != nil {
		return Token{}, err
	}
	return tokenFromGen(row), nil
}

func (s *SQLite) Revoke(ctx context.Context, id string, when time.Time) error {
	n, err := s.q.RevokeToken(ctx, sqlcgen.RevokeTokenParams{
		RevokedAt: nullInt64FromUnix(when),
		ID:        id,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) RevokeTokensByOwner(ctx context.Context, ownerUserID string, when time.Time) (int64, error) {
	return s.q.RevokeTokensByOwner(ctx, sqlcgen.RevokeTokensByOwnerParams{
		RevokedAt:   nullInt64FromUnix(when),
		OwnerUserID: sql.NullString{String: ownerUserID, Valid: true},
	})
}

func (s *SQLite) ExpireEphemeralTokensIdle(ctx context.Context, when time.Time, idleCutoff time.Time) (int64, error) {
	return s.q.ExpireEphemeralTokensIdle(ctx, sqlcgen.ExpireEphemeralTokensIdleParams{
		RevokedAt:  nullInt64FromUnix(when),
		LastUsedAt: nullInt64FromUnix(idleCutoff),
		CreatedAt:  idleCutoff.UTC().UnixNano(),
	})
}

func (s *SQLite) UpdateTokenOwner(ctx context.Context, id string, ownerUserID *string) error {
	n, err := s.q.UpdateTokenOwner(ctx, sqlcgen.UpdateTokenOwnerParams{
		OwnerUserID: nullStringPtr(ownerUserID),
		ID:          id,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- PushSubscriptionStore ---------------------------------------------------

func pushFromGen(r sqlcgen.PushSubscription) PushSubscription {
	return PushSubscription{
		ID:                  r.ID,
		Source:              r.Source,
		TargetURL:           r.TargetUrl,
		SigningSecretHash:   r.SigningSecretHash,
		Name:                r.Name,
		Cursor:              r.Cursor,
		PausedAt:            timePtrFromNullInt64(r.PausedAt),
		CreatedAt:           time.Unix(0, r.CreatedAt).UTC(),
		LastAttemptAt:       timePtrFromNullInt64(r.LastAttemptAt),
		LastSuccessAt:       timePtrFromNullInt64(r.LastSuccessAt),
		LastError:           r.LastError,
		ConsecutiveFailures: int(r.ConsecutiveFailures),
		OwnerUserID:         ptrFromNullString(r.OwnerUserID),
	}
}

func (s *SQLite) InsertPush(ctx context.Context, sub PushSubscription) error {
	return s.q.InsertPushSubscription(ctx, sqlcgen.InsertPushSubscriptionParams{
		ID:                sub.ID,
		Source:            sub.Source,
		TargetUrl:         sub.TargetURL,
		SigningSecretHash: sub.SigningSecretHash,
		Name:              sub.Name,
		Cursor:            sub.Cursor,
		PausedAt:          nullInt64FromTime(sub.PausedAt),
		CreatedAt:         sub.CreatedAt.UTC().UnixNano(),
		OwnerUserID:       nullStringPtr(sub.OwnerUserID),
	})
}

func (s *SQLite) ListPush(ctx context.Context, includePaused bool) ([]PushSubscription, error) {
	flag := int64(0)
	if includePaused {
		flag = 1
	}
	rows, err := s.q.ListPushSubscriptions(ctx, flag)
	if err != nil {
		return nil, err
	}
	out := make([]PushSubscription, 0, len(rows))
	for _, r := range rows {
		out = append(out, pushFromGen(r))
	}
	return out, nil
}

func (s *SQLite) ListPushBySource(ctx context.Context, source string, includePaused bool) ([]PushSubscription, error) {
	flag := int64(0)
	if includePaused {
		flag = 1
	}
	rows, err := s.q.ListPushSubscriptionsBySource(ctx, sqlcgen.ListPushSubscriptionsBySourceParams{
		Source:        source,
		IncludePaused: flag,
	})
	if err != nil {
		return nil, err
	}
	out := make([]PushSubscription, 0, len(rows))
	for _, r := range rows {
		out = append(out, pushFromGen(r))
	}
	return out, nil
}

func (s *SQLite) ListPushByOwner(ctx context.Context, ownerUserID string, includePaused bool) ([]PushSubscription, error) {
	flag := int64(0)
	if includePaused {
		flag = 1
	}
	rows, err := s.q.ListPushSubscriptionsByOwner(ctx, sqlcgen.ListPushSubscriptionsByOwnerParams{
		OwnerUserID:   sql.NullString{String: ownerUserID, Valid: true},
		IncludePaused: flag,
	})
	if err != nil {
		return nil, err
	}
	out := make([]PushSubscription, 0, len(rows))
	for _, r := range rows {
		out = append(out, pushFromGen(r))
	}
	return out, nil
}

func (s *SQLite) ListSystemPush(ctx context.Context, includePaused bool) ([]PushSubscription, error) {
	flag := int64(0)
	if includePaused {
		flag = 1
	}
	rows, err := s.q.ListSystemPushSubscriptions(ctx, flag)
	if err != nil {
		return nil, err
	}
	out := make([]PushSubscription, 0, len(rows))
	for _, r := range rows {
		out = append(out, pushFromGen(r))
	}
	return out, nil
}

func (s *SQLite) GetPush(ctx context.Context, id string) (PushSubscription, error) {
	row, err := s.q.GetPushSubscription(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return PushSubscription{}, ErrNotFound
	}
	if err != nil {
		return PushSubscription{}, err
	}
	return pushFromGen(row), nil
}

func (s *SQLite) UpdateCursorAndSuccess(ctx context.Context, id string, cursor int64, when time.Time) error {
	n, err := s.q.UpdatePushCursorSuccess(ctx, sqlcgen.UpdatePushCursorSuccessParams{
		Cursor:        cursor,
		LastAttemptAt: nullInt64FromUnix(when),
		LastSuccessAt: nullInt64FromUnix(when),
		ID:            id,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) RecordFailure(ctx context.Context, id string, when time.Time, errMsg string) error {
	if len(errMsg) > 1024 {
		errMsg = errMsg[:1024]
	}
	n, err := s.q.RecordPushFailure(ctx, sqlcgen.RecordPushFailureParams{
		LastAttemptAt: nullInt64FromUnix(when),
		LastError:     errMsg,
		ID:            id,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) PausePush(ctx context.Context, id string, when time.Time) error {
	n, err := s.q.PausePushSubscription(ctx, sqlcgen.PausePushSubscriptionParams{
		PausedAt: nullInt64FromUnix(when),
		ID:       id,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) ResumePush(ctx context.Context, id string) error {
	n, err := s.q.ResumePushSubscription(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) RotatePushSecret(ctx context.Context, id, newHash string) error {
	n, err := s.q.RotatePushSecret(ctx, sqlcgen.RotatePushSecretParams{
		SigningSecretHash: newHash,
		ID:                id,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) DeletePush(ctx context.Context, id string) error {
	n, err := s.q.DeletePushSubscription(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) PausePushByOwner(ctx context.Context, ownerUserID string, when time.Time) (int64, error) {
	return s.q.PausePushSubscriptionsByOwner(ctx, sqlcgen.PausePushSubscriptionsByOwnerParams{
		PausedAt:    nullInt64FromUnix(when),
		OwnerUserID: sql.NullString{String: ownerUserID, Valid: true},
	})
}

func (s *SQLite) UpdatePushOwner(ctx context.Context, id string, ownerUserID *string) error {
	n, err := s.q.UpdatePushOwner(ctx, sqlcgen.UpdatePushOwnerParams{
		OwnerUserID: nullStringPtr(ownerUserID),
		ID:          id,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- helpers (preserved API) -------------------------------------------------

func splitScopes(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func cloneHeaders(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
