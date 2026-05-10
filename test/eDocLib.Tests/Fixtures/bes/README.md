# Synthetic BES fixtures (ASiC-E on disk)

Committed **binary** containers for tests that exercise **reading real files** from `Fixtures/bes/` (not only in-memory builds).

| File | Role |
|------|------|
| `synthetic-bes-anchor.cer` | DER of the primary self-signed RSA signer (`Bes Synthetic Fixture Signer`). |
| `synthetic-bes-parallel-co-anchor.cer` | Second RSA signer used only for the dual-signature sample. |
| `synthetic-bes-ecdsa-p256-anchor.cer` | Self-signed ECDSA P-256 signer for the ECDSA fixture. |
| `synthetic-bes-single.edoc` | One payload `doc.txt`, one XAdES-BES signature (RSA-SHA256). |
| `synthetic-bes-single.asice` | **Same octets** as `synthetic-bes-single.edoc`; alternate extension only. |
| `synthetic-bes-single.asic` | Same octets again (some deployments use `.asic`). |
| `synthetic-bes-rsa-sha384.edoc` | RSA with **SHA-384** digest/signature methods (`sha384-doc.txt`). |
| `synthetic-bes-ecdsa-p256.edoc` | ECDSA P-256 / SHA-256 (`ec-note.txt`). |
| `synthetic-bes-parallel-sigs.edoc` | One payload `shared.txt`, **two** RSA signatures (different signers). |
| `synthetic-bes-multi.edoc` | Three payload entries under `bundle/` and root, one signature covering all. |
| `synthetic-bes-empty.edoc` | Zero-length payload `empty.dat`. |
| `synthetic-bes-unicode-path.edoc` | Single payload with a non-ASCII relative path segment. |

Regenerate (new keys / new signatures):

```bash
dotnet run --project tools/BesEdocFixtureGen/BesEdocFixtureGen.csproj
```

Optional output directory:

```bash
dotnet run --project tools/BesEdocFixtureGen/BesEdocFixtureGen.csproj -- path/to/out
```

Commit updated bytes only when validation or generator behaviour intentionally changes.
