# Celery live pre-attempt 1 diagnostic

The first local attempt used a 12-second HTTP client timeout. The first
`POST /cpag/synthetic` timed out on the client, while the uvicorn access log
subsequently showed `202 Accepted`. The harness therefore stopped before any
queue or worker assertion. The disposable Compose project was cleaned up.

The original JSON/log files were overwritten by the second attempt before they
were archived. This note records the observed failure from the execution
output; it is **not** a replacement for the original raw logs. The client
timeout was raised to 60 seconds before the next attempt.
