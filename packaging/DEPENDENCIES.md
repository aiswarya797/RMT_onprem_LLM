# Packaging dependency record

Checked 2026-09-15 against the npm registry and pinned exactly in `web/package.json` plus `web/package-lock.json`.

| Package | Pin | Use | Declared license | Node compatibility checked |
|---|---:|---|---|---|
| react | 19.3.0 | shipped UI | MIT | yes |
| react-dom | 19.3.0 | shipped UI | MIT | yes |
| scheduler | 0.28.0 | shipped transitively by ReactDOM | MIT | yes |
| vite | 8.3.0 | build only | MIT | Node `^20.19.0 || >=22.12.0` |
| typescript | 7.0.2 | build only | Apache-2.0 | Node `>=16.20.0` |
| vitest | 5.0.1 | test only | MIT | Node `^22.12.0 || ^24.0.0 || >=26.0.0` |
| jsdom | 30.0.1 | test only | MIT | Node `^22.22.2 || ^24.15.0 || >=26.0.0` |
| @testing-library/react | 16.3.3 | test only | MIT | Node `>=18` |
| @testing-library/user-event | 14.6.7 | test only | MIT | Node `>=12` |
| @vitejs/plugin-react | 6.1.1 | build only | MIT | Node `^20.19.0 || >=22.12.0` |
| @types/node | 22.20.2 | build only | MIT | yes |
| @types/react | 19.3.0 | build only | MIT | yes |
| @types/react-dom | 19.3.0 | build only | MIT | yes |

The shipped web-bundle notices are generated from the locked production dependency license files. The release SBOM uses the compiled Go package graph and includes `github.com/mattn/go-sqlite3` v1.14.52, `golang.org/x/crypto` v0.57.0 and SQLite 3.53.4 bundled by go-sqlite3. `golang.org/x/sys` v0.48.0 remains a pinned indirect source requirement but was absent from the final U02 compiled-package graph. Distribution notices for the compiled dependencies and the pinned indirect requirement are checked in under `packaging/licenses/`.

The live-monitoring codec adds exactly pinned `github.com/fxamacker/cbor/v2`
v2.9.3 (MIT), `github.com/x448/float16` v0.8.4 (MIT, transitive), and
`github.com/klauspost/compress` v1.20.0. The latter's module license includes
BSD-3-Clause, Apache-2.0 and MIT sections; RMT imports its zstd codec. Complete
upstream module license texts from the verified module cache are retained in
`packaging/licenses/` and included in generated distribution notices. The SBOM
continues to derive inclusion from the compiled package graph. This dependency
record does not claim a new release build or security audit has passed.

Encrypted backup streaming uses the reference `filippo.io/age` Go library at
exact pin v1.3.2 (BSD-3-Clause), released 2026-08-29. RMT accepts only native
X25519 recovery identities generated for this product; it does not load age
plugins or SSH identities. The compiled package graph also includes the exact
v0.4.0 pin of `filippo.io/hpke` (BSD-3-Clause) used by the age package. Exact
upstream license texts from the checksummed project module cache are retained
as `filippo.io-age.txt` and `filippo.io-hpke.txt`. The age v1 file format is a
streaming authenticated-encryption boundary; archive entry, size, manifest and
SQLite validation remain RMT responsibilities.

Security checks use `npm audit --omit=dev` for the shipped dependency tree and `npm audit` for the complete build/test tree. A clean registry audit is advisory evidence only; it does not prove source reachability, native SQLite coverage or release security. The actual 2026-09-15 command results are recorded in `docs/implementation/u02-build-evidence.json` by the integration owner.
