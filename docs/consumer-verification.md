# Verifying push deliveries

Every push the relay sends carries:

- `X-Hooks-Signature: t=<unix>,v1=<lowercase-hex>`
- `X-Hooks-Delivery-Id`
- `X-Hooks-Sequence`
- `X-Hooks-Source`
- All non-hop-by-hop headers from the original provider delivery (e.g. `Content-Type`).

The signing string is `<unix>.<body>`, and `v1 = HMAC-SHA256(signing_secret, <unix>.<body>)` with lowercase-hex output.

Below are minimal verifiers. All examples reject:

1. Missing or malformed `X-Hooks-Signature`.
2. Timestamp older than 5 minutes (so a leaked-and-replayed POST is rejected).
3. HMAC mismatch.

## Go

```go
package webhooks

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "io"
    "net/http"
    "strconv"
    "strings"
    "time"
)

func Verify(secret string) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        body, err := io.ReadAll(r.Body)
        if err != nil { http.Error(w, "read body", 400); return }
        if err := verifyHooksSignature(secret, r.Header.Get("X-Hooks-Signature"), body, time.Now()); err != nil {
            http.Error(w, err.Error(), 401)
            return
        }
        // Process the event. Idempotency by X-Hooks-Delivery-Id.
        w.WriteHeader(204)
    })
}

func verifyHooksSignature(secret, header string, body []byte, now time.Time) error {
    var t, v1 string
    for _, p := range strings.Split(header, ",") {
        kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
        if len(kv) != 2 { continue }
        switch kv[0] {
        case "t": t = kv[1]
        case "v1": v1 = kv[1]
        }
    }
    if t == "" || v1 == "" { return errors.New("missing X-Hooks-Signature") }

    sec, err := strconv.ParseInt(t, 10, 64)
    if err != nil { return errors.New("malformed t") }
    if d := now.Unix() - sec; d < -300 || d > 300 {
        return errors.New("timestamp outside 5min window")
    }

    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write([]byte(t)); mac.Write([]byte(".")); mac.Write(body)
    want := hex.EncodeToString(mac.Sum(nil))
    if !hmac.Equal([]byte(want), []byte(v1)) { return errors.New("signature mismatch") }
    return nil
}
```

## Node.js

```js
const crypto = require("node:crypto");

function verifyHooksSignature(secret, header, body, nowMs) {
  const parts = Object.fromEntries(
    header.split(",").map(p => p.trim().split("=", 2)).filter(kv => kv.length === 2)
  );
  if (!parts.t || !parts.v1) throw new Error("missing X-Hooks-Signature");
  const tSec = Number(parts.t);
  if (!Number.isFinite(tSec)) throw new Error("malformed t");
  const drift = Math.abs(nowMs / 1000 - tSec);
  if (drift > 300) throw new Error("timestamp outside 5min window");

  const want = crypto.createHmac("sha256", secret).update(`${parts.t}.`).update(body).digest("hex");
  const ok = crypto.timingSafeEqual(Buffer.from(want, "hex"), Buffer.from(parts.v1, "hex"));
  if (!ok) throw new Error("signature mismatch");
}
```

## curl smoke test

You can hand-verify a delivery by replaying it through `openssl`:

```sh
SECRET='your-signing-secret'
T=$(date +%s)
BODY='{"hello":"world"}'
SIG=$(printf '%s.%s' "$T" "$BODY" | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $2}')
curl -sS -X POST "https://my-svc.example.com/hooks" \
  -H "Content-Type: application/json" \
  -H "X-Hooks-Signature: t=$T,v1=$SIG" \
  --data "$BODY"
```

This is exactly what the relay does, so if your server accepts this, it will accept real pushes.
