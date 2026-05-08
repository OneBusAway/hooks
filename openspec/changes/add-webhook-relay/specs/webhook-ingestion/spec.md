## ADDED Requirements

### Requirement: Per-source ingestion endpoints

The service SHALL expose a distinct HTTP endpoint per configured source at `POST /ingest/<source>`, where `<source>` matches a source identifier in the configuration file. Requests to undefined sources SHALL be rejected with HTTP 404.

#### Scenario: Configured source accepts requests
- **WHEN** a `POST /ingest/render` request arrives and `render` is a configured source
- **THEN** the request enters the verification pipeline for that source

#### Scenario: Unknown source is rejected
- **WHEN** a `POST /ingest/unknown-provider` request arrives and no such source is configured
- **THEN** the service responds with HTTP 404 and does not write anything to the event store

### Requirement: Strict verification configuration

Every configured source SHALL declare a registered `Verifier` at startup. The configuration loader SHALL refuse to start the service if a source declares no verifier, names a verifier that is not registered, or has an empty signing secret.

#### Scenario: Source without a verifier fails to start
- **WHEN** the configuration includes a source whose `verifier` field is empty or names a non-registered verifier
- **THEN** the service fails to start with an explicit error message naming the offending source

#### Scenario: Source with empty secret fails to start
- **WHEN** a configured source's secret resolves to the empty string (e.g. unset `${VAR}`)
- **THEN** the service fails to start with an explicit error message naming the offending source

### Requirement: Cryptographic signature verification

The service SHALL verify each inbound webhook against the source's configured secret using the provider-specific signing algorithm before persisting it. Verification MUST use a constant-time comparison. Requests with missing, malformed, or invalid signatures SHALL be rejected with HTTP 401 and SHALL NOT be written to the event store.

#### Scenario: Render-signed request with a valid HMAC is accepted
- **WHEN** a request to `/ingest/render` arrives with a `Render-Webhook-Signature` header whose `v1` value is the HMAC-SHA256 of `<timestamp>.<body>` using the configured Render secret
- **THEN** the request passes verification and proceeds to the timestamp check

#### Scenario: Tampered body is rejected
- **WHEN** a request arrives with a valid-looking signature header but a body that does not match the signature
- **THEN** the service responds with HTTP 401 and does not persist the event

#### Scenario: Missing signature header is rejected
- **WHEN** a request arrives without the source's required signature header
- **THEN** the service responds with HTTP 401 and does not persist the event

### Requirement: Replay-window enforcement

The service SHALL reject any inbound webhook whose provider-supplied timestamp is more than 5 minutes from the server's current time. The skew window SHALL be configurable per source with a default of 5 minutes.

#### Scenario: Stale request is rejected
- **WHEN** a request arrives with a timestamp 10 minutes in the past
- **THEN** the service responds with HTTP 401 and does not persist the event

#### Scenario: Future-dated request is rejected
- **WHEN** a request arrives with a timestamp 10 minutes in the future
- **THEN** the service responds with HTTP 401 and does not persist the event

#### Scenario: Within-window request is accepted
- **WHEN** a request arrives with a timestamp 30 seconds in the past and a valid signature
- **THEN** verification succeeds

### Requirement: Durable accept before acknowledgement

The service SHALL persist the verified event to durable storage and confirm the write before responding with HTTP 2xx to the provider. If persistence fails, the service SHALL respond with HTTP 5xx so the provider can retry.

#### Scenario: Successful ingestion returns 202 only after fsync
- **WHEN** a verified webhook is written to the event store and the store confirms durability
- **THEN** the service responds with HTTP 202 and an empty body

#### Scenario: Storage failure surfaces as 5xx
- **WHEN** the event store returns an error during persistence
- **THEN** the service responds with HTTP 503 so the provider will retry, and logs the failure

### Requirement: Delivery deduplication

The service SHALL deduplicate inbound webhooks by `delivery_id` within a 24-hour window. The `delivery_id` SHALL come from a provider-specific header (e.g. `Render-Webhook-Id`) when available; otherwise it SHALL be a SHA-256 hash of the canonical signing string. A duplicate SHALL be acknowledged with HTTP 200 but SHALL NOT produce a second event-store entry and SHALL NOT trigger any subscriber notification.

#### Scenario: Provider redelivery is deduplicated
- **WHEN** the provider redelivers a webhook with the same `delivery_id` an hour after the original
- **THEN** the service responds with HTTP 200, does not write a new event-store row, and does not notify subscribers a second time

#### Scenario: Distinct deliveries with identical bodies are both stored
- **WHEN** two webhooks arrive with different `delivery_id` values but identical bodies
- **THEN** both are persisted as separate events

### Requirement: Provider-pluggable verifier interface

The verification logic SHALL be implemented behind a `Verifier` interface so additional sources can be added without modifying the ingestion HTTP handler. Each source plugin SHALL declare the headers it requires, the signing-string construction, the timestamp extraction, and the `delivery_id` extraction.

#### Scenario: New source plugin registers cleanly
- **WHEN** a developer adds a new file under `internal/sources/<name>` that implements the `Verifier` interface and registers itself
- **THEN** the service exposes `/ingest/<name>` after a restart with no changes to the ingestion handler

### Requirement: Full request capture

The service SHALL capture, for every accepted webhook: the raw request body, every request header, the source identifier, the resolved `delivery_id`, the verified provider timestamp, and the server-side received-at time. The captured bytes SHALL be the exact bytes that were signed.

#### Scenario: Stored event preserves the bytes that were signed
- **WHEN** an event is persisted
- **THEN** re-running the source's signature verification against the stored body and the original signature header succeeds

### Requirement: Body size limit

The service SHALL enforce a configurable maximum request body size (default 1 MiB) and reject larger requests with HTTP 413 before reading them into memory. The limit SHALL be overridable per source.

#### Scenario: Oversized body is rejected
- **WHEN** a request arrives with a Content-Length larger than the configured limit
- **THEN** the service responds with HTTP 413 and does not buffer the body

#### Scenario: Per-source override applies
- **WHEN** a source is configured with `body_size_limit: 5MiB` and a 3 MiB request arrives for that source
- **THEN** the request is accepted (passing other checks)
