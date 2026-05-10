# Synthetic LT fixtures (EP-13)

- **`synthetic-ocsp-lt.edoc`** — ASiC-E with one XAdES-BES signature, **`RevocationValues`** embedding a **valid OCSP** response (issuer-signed) for the signer certificate.
- **`synthetic-ocsp-lt-anchor.cer`** — DER encoding of the **synthetic CA** used as PKIX trust anchor in tests (not a production root).

Regenerate (new random keys / new OCSP binding):

```bash
dotnet run --project tools/LtFixtureGen/LtFixtureGen.csproj
```

Defaults write into this directory. Commit updated bytes only when behaviour under test should change.
