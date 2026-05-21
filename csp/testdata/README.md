# csp/testdata

Test and benchmark fixtures for the `csp` package. The fixtures are **not
committed** to the repository because the supplied signatures contain real
PII (the signer's surname, СНИЛС and ИНН embedded in the X.509 Subject).

`cades_test.go` and `cades_bench_test.go` call `loadFixture`, which
`t.Skipf` / `b.Skipf` when the file is missing — so a fresh clone of the
repository still builds and passes `go test ./...`, the
CAdES-specific subtests simply skip.

## Required fixtures for the full suite

| Path | Purpose | Provenance |
|---|---|---|
| `good.xml` | document data | any non-binary file, ~10 KB |
| `good.xml.sig` | detached PKCS#7 signature over `good.xml`, signed by a cert whose issuing CA's root cert lives in the host `mroot` store | freshly generated with `cryptcp -sign -detached` against a working CryptoPro cert |
| `expired.xml` + `expired.xml.sig` | detached pair where the signer cert is past `NotAfter` | used by the table-driven `expired` case; can be any older pair from production logs |
| `ca/*.{p7b,cer,crt}` | root certificates installed into `mroot` via `certmgr -inst -store mroot -f` at container startup | snapshot of the consumer service's CA bundle |
| `revoked.xml` + `revoked.xml.sig` | *(future)* signature whose signer cert has been revoked by its issuing CA, with the CRL reachable | for `revoked` subtest — pending external delivery |


## Why not commit the fixtures?

The signature payload includes the signer's full name, СНИЛС and ИНН in
the X.509 Subject, plus a `cdp` URL pointing at the issuing CA's CRL
distribution point. Committing it to a public repository would publish
this identifying information indefinitely. A future improvement would be
to synthesise fixtures via a local test CA on GOST algorithms, but that
needs `gost-engine` plumbing — out of scope for now.
