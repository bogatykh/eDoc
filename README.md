# eDocLib

**eDocLib** is a **.NET 8** library for the Latvian **eDoc** electronic document container: **ASiC-E** packaging, **XML-DSig** / **XAdES** signing and validation, optional **PKIX**, **OCSP/CRL** (embedded and online), **trusted lists (TSL)** integration, and **RFC 3161** timestamps. Behaviour follows **public** standards and EU tooling ([Normative references](#normative-references)).

| | |
|---|---|
| **Target** | `net8.0` (`src/eDocLib/eDocLib.csproj`) |
| **License** | [MIT](LICENSE) |
| **Tests** | `dotnet test` — `test/eDocLib.Tests` |

---

## API evolution (pre-stability)

**eDocLib is under active development.** Until we ship a **1.0** release with an explicit stability statement, **the public API may change between versions**, including **breaking** changes to types, members, defaults, and validation behaviour, as we tighten alignment with published specs and real-world documents.

- **Downstream apps** should **pin** a **Git commit** or an **exact** package / pre-release **version**; avoid floating `*` ranges.
- **After 1.0**, we plan to treat **SemVer** as the contract for the documented public surface, with any intentional breaks called out in release notes.

---

## Capabilities

### ASiC-E container

- MIME type `application/vnd.etsi.asic-e+zip`, first ZIP entry **`mimetype`** (stored).
- **OASIS** `META-INF/manifest.xml` read/write and consistency checks with payload.
- Signatures under **`META-INF/signatures*.xml`** (multiple parallel signatures supported).
- Format probe (**`AsicContainerFormatProbe`**) for seekable streams.
- Large payload handling: spill directory and in-memory threshold live on **`EdocLibConfig`**; open with **`Edoc.Open(EdocLibConfig, stream)`** or **`Edoc.Open(EdocLibConfig, path)`**. For the same defaults as **`EdocLibConfig.Default`**, you can also build a snapshot with **`EdocLibConfigBuilder.CreateDefault().Build()`** and adjust TSL relay, TSP routes, spill paths, or online-revocation hints before calling **`Build()`**.

### XAdES / XML-DSig

- **XAdES-BES** baseline: detached **`Reference`** digests, **`SignedProperties`**, **`SigningTime`**, signer cert in **`KeyInfo`**.
- **Algorithms:** RSA-SHA256 (default), optional RSA-SHA384; **ECDSA** P-256 / P-384 / **P-521** with matching digest URIs (`XadesSigningProfile`, `XadesSignatureAlgorithms`).
- **Exclusive canonicalization** for `SignedInfo` / `SignedProperties` (`XmlDsigCanonicalization`, `DetachedSignatureVerifier`).
- **ESS `SigningCertificate`:** CertDigest + IssuerSerial verification (`SigningCertificateDigestVerifier`); optional policies (`RequireXadesSigningCertificate`, `RestrictSigningCertificateDigestToSha256`).
- **XAdES-T:** RFC 3161 **`SignatureTimeStamp`** (`SignWithTimestampAsync`, `AppendSignatureTimestampAsync`, `Rfc3161HttpTimestampProvider`); imprint vs **`SignatureValue`** (`SignatureTimestampVerifier`, `SignatureTimestampImprintPolicy`).
- **XAdES-LT-style material:** `certificateValues`, `revocationValues`, PKCS#7 certificate bags where applicable (`EdocLongTermSigningJob`, `AppendUnsigned*` helpers).
- **XAdES-LTA / archive timestamps:** `AppendArchiveTimeStamp`, `EdocArchiveSigningJob`, CMS / chain / imprint validation flags on **`SignatureTrustPolicy`** (full national LTA profile rules remain host- and policy-dependent).
- **Signer roles & production place:** parse and emit; optional validation constraints on claimed roles.

### Cryptographic validation

- Reference digests and RSA/ECDSA signature verification over canonical **`SignedInfo`**.
- Optional **PKIX** chain build (`SignatureTrustPolicy.ValidateCertificateChain`, `CustomTrustAnchors`, OS trust store, **`ExtraChainCertificates`**).
- **Revocation:** unsigned **`RevocationValues`** verification (**`EmbeddedRevocationVerifier`**); application-controlled **HTTP OCSP/CRL** after chain build via **`ApplicationOnlineRevocation`** and **`SignatureTrustPolicy.RevocationHttpClient`** when online revocation is enabled; optional **disk cache** for DER (**`DirectoryRevocationDerCache`**); optional **delta CRL** after base CRL when **`RevocationFetchDeltaCrlViaFreshestCdp`** is set (Freshest CRL extension, RFC 5280).
- **TSL / qualification:** **`TrustedListReader`**, **`TrustedListServiceIndex`**, **`TrustedListQualificationResolver`**, mapping options (**`TslQualificationMappingOptions`**, **`TslQualificationMappingDefaults`**), XML signature verification for published lists (**`TrustedListXmlSignatureVerifier`**).
- **Reporting:** hierarchical **`ValidationResultNode`** trees, **`DocumentValidationReport`**, localization (**`IValidationReportLocalizer`**, RESX), optional validation reports on open (**`BuildValidationReport`**).

### Trust material loading

- **`TrustAnchorLoader`**: PEM, PKCS#12/PFX, **JKS** (Java keystore) for **`SignatureTrustPolicy.CustomTrustAnchors`**.

### Configuration helpers

- **`EdocLibConfig.Default`**, **`EdocLibConfigBuilder.CreateDefault()`**, **`Edoc.Open`** / **`Edoc.OpenAndValidateAsync`**, **`TimestampResponderRegistry.RegisterFrom`**, **`EdocLibConfig.ResolveFetchDeltaCrlViaFreshestCdp`**. Map host configuration into a builder or your own snapshot.

---

## Normative references

Implementation work is traced to public artefacts such as:

| Area | Typical references |
|------|-------------------|
| Container | **ETSI EN 319 162** (ASiC) |
| XAdES | **ETSI EN 319 132**, baseline AdES **EN 319 102-1** / **TS 119 102-2** |
| TSL | **ETSI TS 119 612**, EU LOTL tooling |
| PKIX / CRL | **ITU-T X.509**, **RFC 5280** (incl. Freshest CRL / delta CRL distribution) |
| OCSP | **RFC 6960** |
| Timestamps | **RFC 3161** |
| National profile | **EDOC 2.0** (Latvia / LVRTC-published materials) |

Requirements coverage is reflected in **`test/eDocLib.Tests`** and in comments on individual checks where helpful.

---

## Out of scope

PDF signing, smart cards / PKCS#11, legacy EDOC 1.0, batch APIs, and a mandatory global properties singleton are excluded unless added explicitly in a future release.

---

## Repository layout

```
src/eDocLib/          # Single NuGet-style project (eDocLib)
test/eDocLib.Tests/   # xUnit tests
tools/                # Optional tooling (e.g. fixtures), not required at runtime
```

### Source structure (`src/eDocLib`)

| Folder / area | Role |
|---------------|------|
| **`eDocLib`** (project root — shared **`eDocLib`** namespace) | **`Edoc`** (incl. **`CreateNew`**, **`Open`**, **`OpenAndValidateAsync`**), **`EdocValidation`**, **`Configuration.EdocLibConfig`**, **`Configuration.EdocLibConfigBuilder`**, **`EdocBasicSigningJob`**, **`EdocLongTermSigningJob`**, **`EdocArchiveSigningJob`**, **`DataFile`**, **`IContainer`**, **`IValidatableDocument`**, **`EdocException`** / **`EdocFailureKind`**, material profiles |
| **`Asic/`** | ZIP ASiC-E reader/writer, manifest, format probe, payload spill helpers |
| **`Asic/Xades/`** (namespace **`eDocLib.Asic.Xades`**) | **`XadesBesSigner`**, **`XadesSignature`**, **`XadesBesPreparedSignature`**, **`XadesSigningProfile`** / **`XadesRsaDigestPreference`** / **`XadesKeyKind`**, **`CertificateValuesWireFormat`**, C14N, algorithms, LT/LTA unsigned properties (types **`internal`** except the public signing surface above) |
| **`Validation/`** | **`SignatureValidator`**, **`SignatureTrustPolicy`**, PKIX diagnostics, TSL reader/index/qualification, archive timestamp verification, **`DetachedSignatureVerifier`** |
| **`Validation/Reporting/`** | **`ValidationReportFactory`**, **`DocumentValidationReport`**, **`ValidationResultNode`**, localization, text formatter |
| **`Revocation/`** | **Public** policy/caching/artifacts: `IRevocationDerCache`, `DirectoryRevocationDerCache`, `EmbeddedRevocationVerificationOptions`, `RevocationArtifact*` — subfolders: **`Online/`** (HTTP fetch, URI discovery, `CertificateRevocationMaterialFetcher`), **`Protocols/Ocsp`**, **`Protocols/Crl`**, **`Protocols/Der`** (shared certificate/CRL DER reads), **`Verify/`** (embedded/online verifiers), **`Cache/`**, **`Xades/`** (unsigned `RevocationValues` helper) |
| **`Timestamp/`** | **`Rfc3161HttpTimestampProvider`**, **`TimestampResponderRegistry`** |
| **`Configuration/`** | **`EdocLibConfig`**, **`EdocLibConfigBuilder`** (incl. **`CreateDefault()`**); ASiC read fields on **`EdocLibConfig`** |
| **`Trust/`** | **`TrustAnchorLoader`** (PEM / PKCS#12 / JKS anchors for **`SignatureTrustPolicy`**) |
| **`Trust/Tsl/`** | **`HttpTslTrustedListProvider`**, **`CachingTslTrustedListProvider`**, **`NullTrustedListProvider`**, **`ITrustedListProvider`**, **`TrustedListManager`**, **`TslPublicationUris`**, **`EuLotlPointerLocator`** |

Dependencies: **BouncyCastle.Cryptography**, **SharpZipLib**, **System.Security.Cryptography.Xml** (see `eDocLib.csproj`).

---

## Usage examples

Typical namespaces:

```csharp
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Configuration;
using eDocLib.Validation;
using eDocLib.Validation.Reporting;
using eDocLib.Timestamp;
```

### Detect ASiC-E on a seekable stream

```csharp
using var stream = File.OpenRead("candidate.zip");
if (!Edoc.TryDetectContainer(stream, out var probe))
{
    // Not a plausible ASiC-E shell (mimetype / manifest).
    return;
}

// probe.IsLikelyAsicE — quick positive signal; open with Edoc.Open to parse fully.
stream.Position = 0;
```

### Open a container (path or stream)

```csharp
// From file — uses spill / memory limits from EdocLibConfig.Default
using var edoc = Edoc.Open(EdocLibConfig.Default, @"C:\incoming\package.edoc");

// From stream — same defaults; stream should be seekable for typical ZIP layout
await using var stream = File.OpenRead("package.edoc");
using var fromStream = Edoc.Open(EdocLibConfig.Default, stream);
```

Custom read profile (large entries, spill directory):

```csharp
var config = EdocLibConfigBuilder.CreateDefault()
    .WithPayloadSpillTempDirectory(Path.Combine(Path.GetTempPath(), "edoc-spill"))
    .WithPayloadMemoryThresholdBytes(64L * 1024 * 1024)
    .Build();

using var edoc = Edoc.Open(config, "large.edoc");
```

### Inspect payload files

```csharp
foreach (var file in edoc.DataFiles)
{
    Console.WriteLine($"{file.Name} ({file.MimeType})");
    using var copy = new MemoryStream();
    await file.Stream.CopyToAsync(copy);
}
```

### Validate signatures

**One step** — open with default read settings and validate:

```csharp
await using var stream = File.OpenRead("document.edoc");
var result = await EdocValidation.OpenAndValidateAsync(stream, SignatureTrustPolicy.CryptographyOnly);
// result.Edoc — loaded container; dispose when finished
// result.AllSignaturesValid — false if there are no signatures
using (result.Edoc)
{
    Console.WriteLine(result.AllSignaturesValid ? "OK" : "Invalid");
}
```

**Open then validate** (same as `Edoc.OpenAndValidateAsync` when you split the steps):

```csharp
using var edoc = Edoc.Open(EdocLibConfig.Default, "document.edoc");
var result = await edoc.ValidateAsync(SignatureTrustPolicy.CryptographyOnly);
// or: await EdocValidation.ValidateSignaturesAsync(edoc, policy);
```

**Open + validate with explicit config:**

```csharp
await using var stream = File.OpenRead("document.edoc");
var result = await Edoc.OpenAndValidateAsync(EdocLibConfig.Default, stream, SignatureTrustPolicy.CryptographyOnly);
```

Signatures that are not **`XadesSignature`** fail verification with an explanatory error.

### Validation report (tree + plain text)

```csharp
using var stream = File.OpenRead("document.edoc");
var result = await Edoc.OpenAndValidateAsync(EdocLibConfig.Default, stream, SignatureTrustPolicy.CryptographyOnly);
using (result.Edoc)
{
    var policy = SignatureTrustPolicy.CryptographyOnly;
    var report = result.BuildValidationReport(policy);
    Console.WriteLine(report.ToPlainText()); // optional IValidationReportLocalizer
    // report.Root — ValidationResultNode tree for custom UI
}
```

### Create an empty package, add files, save

```csharp
using var pkg = Edoc.CreateNew();
await using (var doc = File.OpenRead("contract.pdf"))
    pkg.AddDataFile(doc, "contract.pdf", "application/pdf");

await using var outStream = File.Create("unsigned.edoc");
pkg.Save(outStream);
```

### Sign XAdES-BES (two-phase, `EdocBasicSigningJob`)

**Prepare** returns **`XadesBesPreparedSignature`**. Sign **`GetSignableBytes()`** with the private key for **`SigningCertificate`**, then **`Complete`**.

```csharp
using var pkg = Edoc.CreateNew();
await using (var doc = File.OpenRead("contract.pdf"))
    pkg.AddDataFile(doc, "contract.pdf", "application/pdf");

using var rsa = RSA.Create(2048);
var req = new CertificateRequest("CN=signer", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

var job = new EdocBasicSigningJob(pkg, cert, DateTimeOffset.UtcNow);
var prepared = job.Prepare();
var signatureOctets = cert.GetRSAPrivateKey()!.SignData(
    prepared.GetSignableBytes(),
    HashAlgorithmName.SHA256,
    RSASignaturePadding.Pkcs1);
job.Complete(prepared, signatureOctets);

await using var outStream = File.Create("signed.edoc");
pkg.Save(outStream);
```

### Sign with long-term material (`EdocLongTermSigningJob`)

Embeds **`CertificateValues`** / **`RevocationValues`** after signing. Supply DER OCSP responses and CRLs from your PKI; optional CA certificates for the chain.

```csharp
using var pkg = Edoc.CreateNew();
await using (var doc = File.OpenRead("contract.pdf"))
    pkg.AddDataFile(doc, "contract.pdf", "application/pdf");

var ltJob = new EdocLongTermSigningJob(pkg, cert, DateTimeOffset.UtcNow)
{
    CaCertificatesToEmbed = Array.Empty<X509Certificate2>(), // optional: new[] { issuerCert }
    // From your infrastructure, e.g. File.ReadAllBytes("signer.ocsp.der"):
    OcspDerBlobs = Array.Empty<byte[]>(),
    CrlDerBlobs = Array.Empty<byte[]>(),
};

var prep = ltJob.Prepare();
var sigBytes = cert.GetRSAPrivateKey()!.SignData(
    prep.GetSignableBytes(),
    HashAlgorithmName.SHA256,
    RSASignaturePadding.Pkcs1);
ltJob.CompleteWithEmbeddedMaterial(prep, sigBytes);
```

### XAdES-T after LT material (RFC 3161 `SignatureTimeStamp`)

Same setup as the long-term job; use **`CompleteWithEmbeddedMaterialAndTimestampAsync`** instead of **`CompleteWithEmbeddedMaterial`**.

```csharp
var prep = ltJob.Prepare();
var sigBytes = cert.GetRSAPrivateKey()!.SignData(
    prep.GetSignableBytes(),
    HashAlgorithmName.SHA256,
    RSASignaturePadding.Pkcs1);

await using var tsp = new Rfc3161HttpTimestampProvider(new Uri("https://tsa.example/rfc3161"));
await ltJob.CompleteWithEmbeddedMaterialAndTimestampAsync(prep, sigBytes, tsp);
```

Or resolve the TSA URL from **`TimestampResponderRegistry`** (e.g. after **`registry.RegisterFrom(EdocLibConfig.Default)`**):

```csharp
var registry = new TimestampResponderRegistry();
registry.RegisterFrom(EdocLibConfig.Default);
using var http = new HttpClient();
await ltJob.CompleteWithEmbeddedMaterialAndTimestampAsync(prep, sigBytes, registry, httpClient: http);
```

### Archive time-stamp (`EdocArchiveSigningJob`)

Appends **`xades:ArchiveTimeStamp`** to an **existing** signature (index into **`Signatures`**). Requires network access to your TSA.

```csharp
// pkg already contains at least one signature (see BES / LT examples above)
var archiveJob = new EdocArchiveSigningJob(pkg);
await using var atsTsp = new Rfc3161HttpTimestampProvider(new Uri("https://tsa.example/rfc3161"));
await archiveJob.AppendArchiveTimeStampAsync(signatureIndex: 0, atsTsp);

await using var outStream = File.Create("with-archive-ts.edoc");
pkg.Save(outStream);
```

### Save only if validation passes

```csharp
var trust = SignatureTrustPolicy.CryptographyOnly;
using var pkg = Edoc.Open(EdocLibConfig.Default, "signed.edoc");
await using var outStream = File.Create("copy.edoc");
pkg.Save(outStream, validateSignaturesFirst: true, trustPolicyForValidation: trust);
```

### PKIX + application-controlled online revocation (sketch)

```csharp
using var http = new HttpClient();
var policy = SignatureTrustPolicy.SystemAnchorsNoRevocation with
{
    RevocationMode = X509RevocationMode.Online,
    RevocationHttpClient = http,
};
policy.ValidateRevocationFetchConfiguration();

using var edoc = Edoc.Open(EdocLibConfig.Default, "document.edoc");
var result = await edoc.ValidateAsync(policy);
```

Combine with **`TrustAnchorLoader`** (PEM / PFX / JKS), optional TSL-backed **`SignatureTrustPolicy`** fields, **`DirectoryRevocationDerCache`**, and **`TimestampResponderRegistry.RegisterFrom(config)`** for production deployments.

---

## Build and test

```bash
dotnet build src/eDocLib/eDocLib.csproj
dotnet test test/eDocLib.Tests/eDocLib.Tests.csproj
```

Optional HTTP smoke for RFC 3161 (CI): environment variable **`EDOC_TEST_HTTP_TSP_URL`** (see tests).

---

## Contributing

See **[CONTRIBUTING.md](CONTRIBUTING.md)** for language and process expectations.

---

## License

This project is licensed under the **MIT License** — see **[LICENSE](LICENSE)**.
