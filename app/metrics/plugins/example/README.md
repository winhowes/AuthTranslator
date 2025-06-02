# Example Metrics Plugin

This directory contains a minimal metrics plugin showing how to track token
usage from the OpenAI API. It is excluded from normal builds with a
`//go:build example` tag so it can serve purely as a reference.

Build or run the proxy with `-tags example` to include this plugin. The
`WriteProm` hook emits a per-caller `authtranslator_tokens_total` counter which
shows up in the `/_at_internal/metrics` endpoint.
