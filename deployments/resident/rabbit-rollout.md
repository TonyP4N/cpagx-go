# v3 RabbitMQ dispatch rollout

## EU fallback, verified 2026-11-10

Argo application `eu-cpag` reported Synced / Healthy at infra commit
`2bc644741bb182ff2a7bbe0743d75e7e92adfaba`. The CPAG manifest is
`gitops/environments/eu/apps/cpag/resources.json` in `pplulee/infra`.
The project revision was `9462eb983fa181e1303baa8222368e561ab0ad2c`.
The API and resident Worker each had one ready replica. Keep the worker's
`hostUsers: false` setting on this shared node.

| Item | Verified fallback |
|---|---|
| API | `docker.io/library/cpag-resident-api@sha256:76f17f08c104581239cb7804817e5df6ec1313213923d2d1f336b19cf925b8e4` |
| Worker | `docker.io/library/cpag-resident-worker@sha256:1d4a37dcde3288d6f23a015c2f21473173fe29b07ddd46c2017d125e7da54cd3` |
| CI AMD64 archive SHA-256 | `92ac5be2b6ee0471acba67657f2200bac40789ef070f41c8fa6dcdbe218fddf0` |
| EU archive | `/var/backups/cpag-resident-9462eb9/images.tar` |
| Known successful synthetic offline run | `6f571980a0f0b4360b49e0f664660d24` |
| Known successful synthetic replay | `3452ac8d1a07b1eea49a240381e2c73b` |

A read-only inventory found no RabbitMQ workload or image in Kubernetes, no
RabbitMQ Docker container, no active rabbitmq-server systemd service, and no
host listener on 5671, 5672 or 15672. An off-host managed broker would require
separate discovery. This inventory did not create an EU broker or change traffic.

## Change window

1. Record the live CPAG Deployments, Secret versions, GitOps manifest and
   database backup immediately before the change. Use encrypted operator storage
   for Secrets. The backup of configuration made *before* the resident cutover
   contains the Kubernetes Job executor and is older than this fallback.
2. Use a persistent RabbitMQ instance, a dedicated vhost and credentials
   restricted to CPAG's queue and exchange. Keep management and AMQP endpoints
   private. Configure storage alerts and verify broker restart with the same PVC.
   Use separate credentials for the consumer and publisher. Do not deploy Redis.
3. Apply the additive queue migration before the matching API and resident
   images. Start with new submissions on poll. Verify that existing work can
   finish. Add the dispatcher credential to the API and mount its read-only
   token file at `/etc/cpag-dispatch/token` in the private relay. Only the
   publisher needs this HTTP credential. Never give it to Celery consumers.
4. Enable the explicit canary dataset selection. Observe the outbox age,
   broker ready/unacknowledged counts, active attempt/lease and published
   artifact digest for each test job. Confirm both original evidence and replay
   results against the resident baseline before widening the selection.

## Rolling back queue dispatch

First route new submissions to poll. Keep the upgraded API, worker, publisher
and broker available for jobs already routed to RabbitMQ. For queued jobs to
be taken by polling, use the coordinator rollback operation and record the job
IDs actually converted. For an executing job, wait for the active attempt and
its publication or recovery fence; if recovery requeues it, include that job in
the next conversion batch. Old messages may still arrive and must be rejected
by the exact-claim endpoint. Do not purge the queue as a way to move tasks.

Verify that no queued/running/recovering Rabbit-routed jobs or publishable
outbox records remain before stopping its publisher and consumer. For a full
binary rollback, restore the exact API/Worker pins and the paired resident
configuration saved at the start of this change. Retain PostgreSQL, migrations,
PVCs, broker storage and all attempt evidence. Validate a poll claim and the
public readiness endpoint after GitOps sync.
