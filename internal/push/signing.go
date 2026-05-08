package push

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
)

// SignatureHeader returns the value of the X-Hooks-Signature header per the
// push-delivery spec: `t=<unix>,v1=<hmac-sha256(secret, "<unix>.<body>")>`.
//
// `unix` is decimal seconds.
func SignatureHeader(secret string, unix int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	tsRaw := strconv.FormatInt(unix, 10)
	mac.Write([]byte(tsRaw))
	mac.Write([]byte("."))
	mac.Write(body)
	return fmt.Sprintf("t=%s,v1=%s", tsRaw, hex.EncodeToString(mac.Sum(nil)))
}
