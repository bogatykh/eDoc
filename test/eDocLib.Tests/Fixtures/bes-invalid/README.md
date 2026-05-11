# Invalid ASiC-E fixtures (negative tests)

Binary ZIPs that are **intentionally broken** for regression on reader and validation error paths. All are **synthetic** (generated in-repo).

| File | Defect |
|------|--------|
| `invalid-wrong-first-entry.edoc` | First local file entry is `META-INF/manifest.xml` instead of `mimetype`. |
| `invalid-mimetype-content.edoc` | First entry is `mimetype` (stored) but body is not `application/vnd.etsi.asic-e+zip`. |
| `invalid-manifest-ghost-file.edoc` | Manifest lists an extra path that is not in the ZIP. |
| `invalid-duplicate-payload-name.edoc` | Two ZIP entries with the same payload name (`doc.txt`). |
| `invalid-digest-mismatch.edoc` | Well-formed container; first byte of `payload.bin` flipped after signing. |
| `invalid-truncated-zip.edoc` | Truncation of an otherwise valid container (ZIP structure incomplete). |
| `invalid-two-mimetype-entries.edoc` | Two stored ZIP entries named `mimetype` before the manifest; reader rejects the duplicate entry (second body is not ASiC-E). |
| `invalid-missing-manifest.edoc` | Valid `mimetype`, payload, and signature ZIP entries — **no** `META-INF/manifest.xml`. |
| `invalid-signature-uri-mismatch.edoc` | Manifest lists `payload.bin`, ZIP holds `payload.bin`, but the detached signature’s `ds:Reference` URIs target `wrong-uri.bin`. |
| `invalid-mimetype-asic-s-body.edoc` | First entry is stored `mimetype`, but body is `application/vnd.etsi.asic-s+zip` (ASiC-S) instead of ASiC-E. |
| `invalid-orphan-payload-not-in-manifest.edoc` | Manifest lists only `payload.bin`; ZIP also contains `orphan-extra.bin` (payload not in manifest). |
| `invalid-parallel-second-signature-corrupt.edoc` | Two `META-INF/signatures*.xml` over the same payload; second file has a corrupted `ds:SignatureValue`. |

Regenerate:

```bash
dotnet run --project tools/BesInvalidFixtureGen/BesInvalidFixtureGen.csproj
```

Optional output directory as first argument. Commit new bytes when generator output or expected failure modes change.
