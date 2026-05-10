# Test fixtures (external / golden material)

## Purpose

This directory is reserved for **binary or XML fixtures** used in tests when they are **not** generated inline (see `test/eDocLib.Tests/Fixtures/` for project-local samples such as minimal TSL XML).

## Redistribution and rights

- Add only artefacts you are **allowed** to commit (license, contract, or public-domain / open publication terms).
- Prefer **synthetic** or **minimally derived** data (e.g. certificates created with `openssl` or `CertificateRequest` in tests) over copying proprietary third-party containers.
- Do **not** treat externally sourced or proprietary sample containers as a normative **source of truth** for eDocLib behaviour unless rights and scope are explicit.

## Anonymization

When reusing production-like files for regression tests:

- Remove or replace personally identifiable information and operational hostnames where not essential to the cryptographic scenario.
- Keep only the minimum structure needed to assert parsing, validation, or protocol behaviour.

## Layout

- **`test/eDocLib.Tests/Fixtures/`** — copied into the test output; good for small XML/DER owned by this repo.
- **`test/eDocLib.Tests/Fixtures/lt/`** — synthetic **LT-style** `.edoc` + CA anchor (EP-13); regenerate via **`tools/LtFixtureGen`** (see that folder’s `README.md`).
- **`test/eDocLib.Tests/Fixtures/bes/`** — synthetic **XAdES-BES** `.edoc` samples + `.asice` alias + anchor `.cer`; regenerate via **`tools/BesEdocFixtureGen`** (see that folder’s `README.md`).
- **`test/eDocLib.Tests/Fixtures/bes-invalid/`** — deliberately broken ASiC-E ZIPs for negative tests; regenerate via **`tools/BesInvalidFixtureGen`** (see that folder’s `README.md`).
- **`test/fixtures/`** (here) — optional shared pool for larger or cross-project artefacts once the above rules are satisfied.
