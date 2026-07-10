# Async & Second-Order Security Audit

Purpose: catch vulnerabilities that are stored through one surface and exploited later by a worker, scheduler, queue consumer, Spark/EMR job, Lambda, CLI, or cron.

## Entry Point Discovery

Run scoped searches and then read matching files:

```bash
rg -n "@Scheduled|cron|Quartz|Scheduler|TimerTask|CommandLineRunner|ApplicationRunner" --type java
rg -n "KafkaListener|RabbitListener|SqsListener|JmsListener|@StreamListener|Consumer<|consume|subscribe|poll\\(" --glob "*.{java,js,ts,py,go}"
rg -n "lambda|Lambda|EMR|Spark|spark-submit|add-steps|Dataproc|Dataflow|Glue|Batch" --glob "*.{java,js,ts,py,sh,yml,yaml,properties,json}"
rg -n "request_body|payload|eligibility|criteria|filter|stored|metadata|json" --glob "*.{java,js,ts,py,go}"
```

Also enumerate:

- Kafka/Rabbit/SQS topics and consumers
- scheduled jobs and activation endpoints
- batch scripts and cloud job submissions
- DB fields storing JSON/filter/template expressions
- file imports that later become SQL, shell args, templates, URLs, or Kafka messages

## Threat Model

For each async flow, map:

```text
HTTP/API/UI/upload/source → persisted field/topic/file → worker/job → sink
```

Common second-order sinks:

- SQL / NoSQL query construction
- shell/command execution
- template rendering
- outbound URL fetch (SSRF)
- deserialization
- file path construction
- Kafka/event publishing with PII
- privilege-changing state transitions

## Mandatory Checks

| Class | What to verify |
|-------|----------------|
| Second-order SQLi | Stored JSON/filter values later concatenated into SQL |
| Queue auth confusion | Consumer trusts message headers/user IDs without producer auth |
| Poisoned events | Attacker can enqueue malformed/privileged messages |
| Worker SSRF | Stored URL later fetched by job |
| Stored template injection | Template/body stored then rendered later |
| File import abuse | CSV/Excel/file fields become SQL/shell/path values |
| Cron activation abuse | User can create/activate job that later runs with service privileges |
| Cross-service trust | Service-to-service token/header is minted or overwritten unsafely |
| PII fanout | Worker logs/publishes sensitive data to broad topics/logs |

## Validation Rules

- G1 source may be earlier than the sink by minutes/hours/days.
- G2 reachability requires a stored-flow trace, not just immediate call-stack reachability.
- DAST may only confirm the write/activation step; execution proof may come from logs, queue messages, job status, timing, or code trace.
- If live execution is unsafe, report as Firm/Tentative with explicit assumptions and Burp/curl request for the storage step.

## Report Requirements

Add to Data Flow Trace:

```text
1. SOURCE: API/UI/upload stores attacker-controlled value in [table/topic/file].
2. PERSISTENCE: [field/topic/path] retains value without validation.
3. TRIGGER: cron/activation/consumer loads the value.
4. SINK: worker/job executes dangerous operation.
```

For second-order findings, include both:

- Burp/curl PoC for the storing request
- worker/job sink snippet proving later execution
