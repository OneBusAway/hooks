## hooks

A small, self-hosted relay that durably captures inbound webhooks (Render to start), verifies their signatures, and re-delivers them to one or more developer environments — either pulled over Server-Sent Events or pushed to a registered URL — including replay of anything missed while disconnected.

To get started: `hooks init`.
