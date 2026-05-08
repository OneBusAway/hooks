package auth

import "errors"

// ErrInvalid is returned by Lookup when the cookie does not match a valid
// session row (malformed value, missing row, hash mismatch, deactivated
// user, etc.). Callers should clear cookies on this error.
var ErrInvalid = errors.New("auth: invalid session")

// ErrExpired is returned by Lookup when the session row exists but has
// passed its expires_at. Callers should clear cookies and prompt for a
// fresh login.
var ErrExpired = errors.New("auth: session expired")

// ErrBadCredentials is returned by Authenticate on either an unknown email
// or a wrong password. The handler maps both to a generic HTTP 401 so the
// API does not leak which axis failed.
var ErrBadCredentials = errors.New("auth: bad credentials")

// ErrDeactivated is returned by Authenticate when the user exists and the
// password is correct but the account is deactivated.
var ErrDeactivated = errors.New("auth: account deactivated")
