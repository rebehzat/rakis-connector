# Source publication boundary

This repository contains only the passive connector client, its synthetic unit
tests, standalone packaging code and client documentation. It was copied as a
file allowlist, without importing private repository history.

Included code implements credential storage, bounded local configuration rules,
HTTP request/response validation and the connector's user service. Optional AI
flags request server-side review; this repository contains no prompts, provider
credentials, model selection, agent orchestration or server analysis logic.

Before updating public source, review every added file for secrets, customer data
and server implementation details. Test fixture credentials must remain obviously
synthetic. Keep generated artifacts and local configuration out of Git. Build
artifacts contain only `acsc_cli/` and the connector distribution metadata.

The private source-upload agent is a separate component and is excluded, along
with backend services, network scanning engines and deployment configuration.
This repository's public availability does not change its proprietary license.
