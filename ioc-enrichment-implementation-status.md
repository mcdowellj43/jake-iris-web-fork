# IOC Enrichment Implementation Status

This document records the current implementation state of the IOC enrichment features described in `ioc-enrichment-implementation.md`. Items are grouped into areas that fully meet the plan and areas that are incomplete or diverge from the design.

## ✅ Implemented as Planned

### Profile Definitions and Management
* The profile manager loads built-in profiles and optional YAML files, with entries for **IP-basic**, **Domain-basic**, and **Hash-basic** matching the plan’s source lists and metadata. 【F:source/app/iris_engine/enrichment/profiles.py†L15-L154】【F:source/app/iris_engine/enrichment/profiles/default.yaml†L1-L36】

### Normalization and Markdown Output
* The enrichment normalizer assembles unified IOC results, applies risk scoring rules for IP, domain, and hash data, and annotates classifications and summaries in line with the specification. 【F:source/app/iris_engine/enrichment/normalizer.py†L13-L193】
* The markdown renderer produces reports with header metadata, executive summaries, key findings, per-source sections, and artifact listings, matching the note-formatting guidance. 【F:source/app/iris_engine/enrichment/markdown_renderer.py†L13-L159】

### GraphQL Exposure
* GraphQL types, queries, and mutations for enrichment are defined and wired into the global GraphQL schema so clients can request profiles and start jobs through the API surface. 【F:source/app/iris_engine/enrichment/graphql_schema.py†L1-L280】【F:source/app/blueprints/graphql/graphql_route.py†L47-L89】

## ⚠️ Missing or Divergent from Plan

### Source Implementations
* Several profile sources (OTX, Whois, crt.sh, URLhaus, Hybrid Analysis, MalwareBazaar) return static placeholder payloads instead of live API integrations, so the enrichment data promised in the plan is unavailable. 【F:source/app/iris_engine/enrichment/sources/rdap.py†L53-L147】
* Other sources in the registry lack configuration plumbing (for example PassiveTotal) or are unused by the shipped profiles, leaving their behaviors untested. 【F:source/app/iris_engine/enrichment/sources/__init__.py†L1-L38】

### Artifact Handling and Note Upserts
* `run_ioc_enrichment` fabricates in-memory artifact identifiers instead of persisting case artifacts with tags as required. 【F:source/app/iris_engine/enrichment/tasks.py†L141-L156】
* The helper that should upsert notes always creates a new note and marks a TODO for searching existing notes, so repeated runs are not idempotent. 【F:source/app/iris_engine/enrichment/tasks.py†L220-L256】

### Job Execution Model
* Enrichment jobs are executed synchronously without Celery task decorators or queue scheduling; the batch helper simply loops over `run_ioc_enrichment`, and the module itself notes that async wiring is still pending. 【F:source/app/iris_engine/enrichment/tasks.py†L46-L197】【F:source/app/iris_engine/enrichment/tasks.py†L259-L299】
* Because `StartEnrichment` calls the synchronous task directly, GraphQL clients block until completion rather than receiving queued job IDs that transition through statuses. 【F:source/app/iris_engine/enrichment/graphql_schema.py†L95-L144】
* The in-memory job manager does not persist state across processes or expose the GraphQL status fields described in the plan beyond the lifetime of the worker. 【F:source/app/iris_engine/enrichment/job_manager.py†L16-L200】

### Frontend Experience
* The IOC table only exposes a “View Enrichment” button for already-populated fields—there is no UI action to trigger profile-based jobs, bulk actions, or the job drawer feedback flow from the plan. 【F:ui/src/pages/alerts.js†L1120-L1199】

### Data Processing Enhancements
* The enrichment storage manager with artifact/note helpers exists but is not used inside the main task flow, leaving caching, tagging, and state updates inactive. 【F:source/app/iris_engine/enrichment/storage.py†L1-L200】
* Configuration, caching, rate limiting, and retry utilities are implemented but never invoked during source execution, so API protection and TTL-based reuse are missing. 【F:source/app/iris_engine/enrichment/config.py†L1-L120】【F:source/app/iris_engine/enrichment/tasks.py†L46-L197】

### Miscellaneous Gaps
* PassiveTotal and Shodan integrations are listed in the registry, yet the shipped default profiles omit them, and no profile gating or RBAC checks exist to reflect the access model outlined in the plan. 【F:source/app/iris_engine/enrichment/profiles/default.yaml†L1-L36】【F:source/app/iris_engine/enrichment/sources/__init__.py†L1-L38】
* Bulk or differential re-run logic, caching invalidation, and scheduled enrichment hooks from the “Next Steps” section are not present. 【F:source/app/iris_engine/enrichment/tasks.py†L259-L299】【F:source/app/iris_engine/enrichment/config.py†L121-L220】

## Summary

While the scaffolding for profiles, normalization, markdown reporting, and GraphQL endpoints exists, the core enrichment behavior is still largely stubbed. The plan’s promises around real data collection, artifact persistence, idempotent note updates, asynchronous job handling, and analyst-facing UI flows have not been realized yet. Completing those areas will bring the implementation in line with the design intent laid out in `ioc-enrichment-implementation.md`.
