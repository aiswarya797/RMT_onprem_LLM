# Same-machine preview verification

Checked 18 September 2026. This records a bounded developer verification, not a production or clean-customer-machine qualification.

## Observed on real hardware

Apple Silicon Mac, 8 GiB RAM, macOS 15.5 (24F74), existing native Ollama 0.12.10. No inference requests, model downloads, certificate imports, privacy-permission changes or outbound notifications were made. The existing installation and Ollama service were preserved. Temporary instances used separate state directories and loopback ports.

The current packaged arm64 binaries (`0.1.0-preview.1`, build `preview-local-20260918`) were extracted from the development archive and run together. The real Codex in-app browser demonstrated:

- First-administrator setup and authenticated dashboard.
- Fresh CPU, memory pressure, compressed memory, swap and disk observations. CPU is displayed as a percentage and memory as binary units; stored measurements retain their original units.
- Ollama reachability and installed model identities. Model digests matched `/api/tags`.
- A saved investigation and note, retained after browser reload.
- Experimental pairing, probes, notification configuration and comparison panels hidden by default.
- No browser JavaScript errors in the observed session.

A preceding run of the same application changes additionally demonstrated sign-out, keyboard sign-in, visible focus, host history selection and collector restart/recovery. The same host identity returned with session generation advancing from 1 to 2. The packaged CLI returned status successfully while its hub was running. Keep-data uninstall's resource preview succeeded against the isolated installation; destructive removal was not needed for this check.

[Resource dashboard screenshot](images/dashboard.png) · [Full dashboard screenshot](images/dashboard-full.png). Both capture actual passive observations. No synthetic measurements were substituted. “Partial” remains visible because some capabilities are unsupported or unavailable. On the existing Ollama version, loaded-state and model-size fields remained unavailable; successful generation and loaded-model accuracy are **not** established.

The two browser sessions completed in approximately 125 and 127 seconds with the hub/collector process tree under the existing 256 MiB guard, normal macOS pressure and no supervisor cleanup errors. Codex's existing browser is outside that process-tree measurement. This is **not** a total-desktop memory benchmark or long-running overhead qualification. Two earlier standalone Chrome attempts exceeded a separate 512 MiB guard before UI assertions and were cleaned up.

## Automated checks

- All Go packages tested once; an outdated internal-query/HTTP-envelope fixture failed. The query fixture was corrected and the affected query/HTTP packages rerun. No production behavior changed for that correction.
- Web typecheck and production build; 40 component tests with one worker.
- 72 Python contract tests, including corrected historical incident/request fixtures for fields introduced by prior implementations.
- 14 packaging contracts, including artifact verification failure cases.
- Development package build, arm64 and minimum-OS checks, ad-hoc signature verification, embedded frontend and checksums.

Commands for developers:

```sh
go test -p 1 -tags sqlite_dbstat ./...
npm --prefix web ci --ignore-scripts
npm --prefix web run build
npm --prefix web test -- --run --maxWorkers=1
python3 -m venv .work/contracts-venv
.work/contracts-venv/bin/pip install -r tests/contracts/requirements.txt
.work/contracts-venv/bin/python -m unittest discover -s tests/contracts -v
python3 -m unittest discover -s tests/packaging -v
```

Use serial builds on memory-constrained hosts. Native listener/process tests may require running outside a restricted sandbox. Fixture tests do not establish hardware correctness. The optional standalone browser smoke requires an installed Playwright module via `PLAYWRIGHT_MODULE`; it was not completed under this Mac's standalone-browser memory budget.

## Artifact identity

| File | SHA-256 |
|---|---|
| `LLM-Monitor-0.1.0-preview.1-development-unsigned.pkg` | `d6e0657472bd03e45b16265068ee8cbd50a4ed8da70df8cdfa9ea1910264bdd2` |
| `LLM-Monitor-0.1.0-preview.1-development-adhoc-darwin-arm64.tar.gz` | `384bf7be038676b9b8f3885d4f9f2f45f2de0f30f9be280540496b9756e2721b` |

## Remaining limits

- Unsigned installer and ad-hoc binaries: no Developer ID notarization or clean-host Gatekeeper acceptance. Assisted developer trials only; never disable system security to install.
- Physical remote activation remains unresolved and gated. Remote code and diagnostics are preserved.
- No successful inference, concurrent-load test, GPU instrumentation, all-traffic request timing, live notification delivery UX or complete comparison UX is claimed.
- The compatibility manifest is a historical unverified source/fixture record; it is not a current certification of every capability or OS version. Actual observations above are narrower.
- No new 72-hour/30-day soak, comprehensive accessibility audit, or independent operator usability study was performed.
- Alerts and recovery have focused automated coverage and prior development evidence. This pass did not induce a live alert or perform a destructive restore on the installed monitor.
