using System.Net.Mime;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using eDocLib;
using eDocLib.Asic.Container;
using eDocLib.Asic.Manifest;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using ICSharpCode.SharpZipLib.Zip;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// Extra ASiC-E scenarios inspired by broad regression corpuses — distinct from
/// <see cref="BesInvalidFixtureFileTests"/>, <see cref="EdocNegativeAndParallelTests"/>, and mutation tests.
/// </summary>
public class AsicContainerAdditionalScenarioTests
{
    [Fact]
    public async Task Mimetype_entry_with_utf8_bom_loads_and_validates()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=bom-mime", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "bom-payload"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-05-10T12:00:00Z"));
        var sigUtf8 = Encoding.UTF8.GetBytes(SerializeSig(sig));

        var manifest = new OasisManifest();
        manifest.Add("doc.txt", "text/plain");

        using var ms = new MemoryStream();
        using (var zos = new ZipOutputStream(ms) { IsStreamOwner = false })
        {
            var mt = new ZipEntry("mimetype") { CompressionMethod = CompressionMethod.Stored };
            zos.PutNextEntry(mt);
            var bomMime = new byte[] { 0xEF, 0xBB, 0xBF }.Concat(Encoding.UTF8.GetBytes(AsicContainer.MimeType)).ToArray();
            zos.Write(bomMime, 0, bomMime.Length);
            zos.CloseEntry();

            var man = new ZipEntry("META-INF/manifest.xml") { CompressionMethod = CompressionMethod.Deflated };
            zos.PutNextEntry(man);
            manifest.Generate().Save(zos);
            zos.CloseEntry();

            var se = new ZipEntry("META-INF/signatures0.xml") { CompressionMethod = CompressionMethod.Deflated };
            zos.PutNextEntry(se);
            zos.Write(sigUtf8, 0, sigUtf8.Length);
            zos.CloseEntry();

            var data = new ZipEntry("doc.txt") { CompressionMethod = CompressionMethod.Deflated };
            zos.PutNextEntry(data);
            zos.Write(payload, 0, payload.Length);
            zos.CloseEntry();
        }

        ms.Position = 0;
        var report = await EdocValidation.OpenAndValidateAsync(ms, SignatureTrustPolicy.CryptographyOnly);
        Assert.True(report.AllSignaturesValid, report.Signatures.ElementAtOrDefault(0)?.Result.Error);
    }

    [Fact]
    public async Task Payload_file_present_in_zip_but_not_in_manifest_rejected_on_load()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=extra", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var listed = "listed.txt"u8.ToArray();
        var extra = "extra-only"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(listed.ToArray()), "listed.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-05-10T13:00:00Z"));

        var manifest = new OasisManifest();
        manifest.Add("listed.txt", "text/plain");

        var zip = ZipTestHelpers.BuildMinimalAsicZip(
            manifest.Generate(),
            new Dictionary<string, byte[]>
            {
                ["listed.txt"] = listed.ToArray(),
                ["extra-unlisted.txt"] = extra.ToArray(),
            },
            new List<byte[]> { Encoding.UTF8.GetBytes(SerializeSig(sig)) });

        var ex = Assert.Throws<AsicException>(() => new Edoc(new MemoryStream(zip)));
        Assert.Contains("extra-unlisted.txt", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not listed", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Malformed_manifest_xml_throws_on_load()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=bad-man", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "x"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "f.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-05-10T15:00:00Z"));

        var badManifest = Encoding.UTF8.GetBytes("<manifest xmlns=\"urn:oasis:names:tc:opendocument:xmlns:manifest:1.0\" broken");

        var zip = ZipTestHelpers.BuildMinimalAsicZipRawManifestUtf8(
            badManifest,
            new Dictionary<string, byte[]> { ["f.txt"] = payload.ToArray() },
            new List<byte[]> { Encoding.UTF8.GetBytes(SerializeSig(sig)) });

        Assert.ThrowsAny<XmlException>(() => new Edoc(new MemoryStream(zip)));
    }

    [Fact]
    public async Task Truncated_signature_xml_throws_on_load()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=trunc-sig", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "q"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "r.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-05-10T16:00:00Z"));

        var manifest = new OasisManifest();
        manifest.Add("r.txt", "text/plain");

        var truncatedSig = Encoding.UTF8.GetBytes("<?xml version=\"1.0\" encoding=\"UTF-8\"?><ds:Signature ");

        var zip = ZipTestHelpers.BuildMinimalAsicZip(
            manifest.Generate(),
            new Dictionary<string, byte[]> { ["r.txt"] = payload.ToArray() },
            new List<byte[]> { truncatedSig });

        Assert.ThrowsAny<XmlException>(() => new Edoc(new MemoryStream(zip)));
    }

    [Fact]
    public async Task Second_zip_entry_with_same_signatures_path_invalid_xml_throws_on_load()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=dup-sig", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "p"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "s.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-05-10T17:00:00Z"));
        var goodSig = Encoding.UTF8.GetBytes(SerializeSig(sig));
        var badSecond = Encoding.UTF8.GetBytes("<not-xml");

        var manifest = new OasisManifest();
        manifest.Add("s.txt", "text/plain");

        var zip = ZipTestHelpers.BuildMinimalAsicZipDuplicateSignatureEntry(
            manifest.Generate(),
            new Dictionary<string, byte[]> { ["s.txt"] = payload.ToArray() },
            goodSig,
            badSecond);

        Assert.ThrowsAny<XmlException>(() => new Edoc(new MemoryStream(zip)));
    }

    [Fact]
    public async Task Reference_uri_percent_encoded_does_not_match_zip_entry_name_fails_validation()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=uri-enc", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var fileName = "a b.txt";
        var payload = "uri-test"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), fileName, "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-05-10T18:00:00Z"));
        var xml = SerializeSig(sig);
        var patched = xml.Replace("URI=\"" + fileName + "\"", "URI=\"a%20b.txt\"", StringComparison.Ordinal);

        var manifest = new OasisManifest();
        manifest.Add(fileName, "text/plain");

        var zip = ZipTestHelpers.BuildMinimalAsicZip(
            manifest.Generate(),
            new Dictionary<string, byte[]> { [fileName] = payload.ToArray() },
            new List<byte[]> { Encoding.UTF8.GetBytes(patched) });

        var report = await EdocValidation.OpenAndValidateAsync(new MemoryStream(zip), SignatureTrustPolicy.CryptographyOnly);
        Assert.False(report.AllSignaturesValid);
        Assert.Contains("Missing payload", report.Signatures[0].Result.Error ?? string.Empty, StringComparison.Ordinal);
        Assert.Contains("%20", report.Signatures[0].Result.Error ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Unsupported_digest_method_uri_throws_NotSupportedException()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=bad-digest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "d"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-05-10T19:00:00Z"));
        var xml = SerializeSig(sig);
        var broken = PatchFirstDetachedReferenceDigestMethod(xml, "http://example.invalid/digest/unsupported-for-tests");

        var manifest = new OasisManifest();
        manifest.Add("doc.txt", "text/plain");

        var zip = ZipTestHelpers.BuildMinimalAsicZip(
            manifest.Generate(),
            new Dictionary<string, byte[]> { ["doc.txt"] = payload.ToArray() },
            new List<byte[]> { Encoding.UTF8.GetBytes(broken) });

        await Assert.ThrowsAsync<NotSupportedException>(async () =>
                await EdocValidation.OpenAndValidateAsync(new MemoryStream(zip), SignatureTrustPolicy.CryptographyOnly)
                    )
            ;
    }

    [Fact]
    public async Task Large_payload_round_trip_validates()
    {
        const int len = 384 * 1024;
        var payload = new byte[len];
        for (var i = 0; i < len; i++)
        {
            payload[i] = (byte)((i * 17 + 41) % 251);
        }

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=large", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "bulk.bin", "application/octet-stream") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-05-10T20:00:00Z"));

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "bulk.bin", "application/octet-stream");
        edoc.AddSignature(sig);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var report = await EdocValidation.OpenAndValidateAsync(zip, SignatureTrustPolicy.CryptographyOnly);
        Assert.True(report.AllSignaturesValid, report.Signatures.ElementAtOrDefault(0)?.Result.Error);
    }

    /// <summary>First ZIP entry must be stored <c>mimetype</c> (some ASiC tooling incorrectly compresses it).</summary>
    [Fact]
    public async Task Mimetype_entry_must_be_uncompressed_stored()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=mime-def", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "v"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-05-11T08:00:00Z"));

        var manifest = new OasisManifest();
        manifest.Add("doc.txt", "text/plain");

        using var ms = new MemoryStream();
        using (var zos = new ZipOutputStream(ms) { IsStreamOwner = false })
        {
            var mt = new ZipEntry("mimetype") { CompressionMethod = CompressionMethod.Deflated };
            zos.PutNextEntry(mt);
            var mime = Encoding.UTF8.GetBytes(AsicContainer.MimeType);
            zos.Write(mime, 0, mime.Length);
            zos.CloseEntry();

            var man = new ZipEntry("META-INF/manifest.xml") { CompressionMethod = CompressionMethod.Deflated };
            zos.PutNextEntry(man);
            manifest.Generate().Save(zos);
            zos.CloseEntry();

            var se = new ZipEntry("META-INF/signatures0.xml") { CompressionMethod = CompressionMethod.Deflated };
            zos.PutNextEntry(se);
            var sx = Encoding.UTF8.GetBytes(SerializeSig(sig));
            zos.Write(sx, 0, sx.Length);
            zos.CloseEntry();

            var data = new ZipEntry("doc.txt") { CompressionMethod = CompressionMethod.Deflated };
            zos.PutNextEntry(data);
            zos.Write(payload, 0, payload.Length);
            zos.CloseEntry();
        }

        ms.Position = 0;
        var ex = Assert.Throws<AsicException>(() => new Edoc(ms));
        Assert.Contains("ZIP storage", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("mimetype", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Mimetype_body_whitespace_only_rejected_on_load()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=mime-ws", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "w"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-05-11T09:00:00Z"));

        var manifest = new OasisManifest();
        manifest.Add("doc.txt", "text/plain");

        using var ms = new MemoryStream();
        using (var zos = new ZipOutputStream(ms) { IsStreamOwner = false })
        {
            var mt = new ZipEntry("mimetype") { CompressionMethod = CompressionMethod.Stored };
            zos.PutNextEntry(mt);
            var ws = Encoding.UTF8.GetBytes("  \t\r\n  ");
            zos.Write(ws, 0, ws.Length);
            zos.CloseEntry();

            var man = new ZipEntry("META-INF/manifest.xml") { CompressionMethod = CompressionMethod.Deflated };
            zos.PutNextEntry(man);
            manifest.Generate().Save(zos);
            zos.CloseEntry();

            var se = new ZipEntry("META-INF/signatures0.xml") { CompressionMethod = CompressionMethod.Deflated };
            zos.PutNextEntry(se);
            var sigUtf8 = Encoding.UTF8.GetBytes(SerializeSig(sig));
            zos.Write(sigUtf8, 0, sigUtf8.Length);
            zos.CloseEntry();

            var data = new ZipEntry("doc.txt") { CompressionMethod = CompressionMethod.Deflated };
            zos.PutNextEntry(data);
            zos.Write(payload, 0, payload.Length);
            zos.CloseEntry();
        }

        ms.Position = 0;
        var ex = Assert.Throws<AsicException>(() => new Edoc(ms));
        Assert.Contains("Invalid MIME type", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Manifest_duplicate_file_entry_full_path_throws_while_parsing()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=dup-fe", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "z"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-05-11T10:00:00Z"));

        var om = new OasisManifest();
        om.Add("doc.txt", "text/plain");
        var md = om.Generate();
        var root = md.Root!;
        var ns = root.Name.Namespace;
        var docFe = root.Elements(ns + "file-entry")
            .First(e => string.Equals(e.Attribute(ns + "full-path")?.Value, "doc.txt", StringComparison.Ordinal));
        root.Add(new XElement(docFe));

        var zip = ZipTestHelpers.BuildMinimalAsicZip(
            md,
            new Dictionary<string, byte[]> { ["doc.txt"] = payload.ToArray() },
            new List<byte[]> { Encoding.UTF8.GetBytes(SerializeSig(sig)) });

        Assert.Throws<ArgumentException>(() => new Edoc(new MemoryStream(zip)));
    }

    [Fact]
    public async Task Unsupported_signature_method_fails_validation_with_known_error_token()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=sig-meth", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "m"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-05-11T11:00:00Z"));
        var patched = PatchSignedInfoSignatureMethod(SerializeSig(sig), "http://example.invalid/signature-rsa-unknown");

        var manifest = new OasisManifest();
        manifest.Add("doc.txt", "text/plain");

        var zip = ZipTestHelpers.BuildMinimalAsicZip(
            manifest.Generate(),
            new Dictionary<string, byte[]> { ["doc.txt"] = payload.ToArray() },
            new List<byte[]> { Encoding.UTF8.GetBytes(patched) });

        var report = await EdocValidation.OpenAndValidateAsync(new MemoryStream(zip), SignatureTrustPolicy.CryptographyOnly);
        Assert.False(report.AllSignaturesValid);
        Assert.Contains("Unsupported SignatureMethod", report.Signatures[0].Result.Error ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Detached_reference_uri_with_leading_slash_does_not_resolve_to_zip_entry_name()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=slash-uri", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "slash"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-05-11T12:00:00Z"));
        var patched = PatchFirstDetachedReferenceUri(SerializeSig(sig), "/doc.txt");

        var manifest = new OasisManifest();
        manifest.Add("doc.txt", "text/plain");

        var zip = ZipTestHelpers.BuildMinimalAsicZip(
            manifest.Generate(),
            new Dictionary<string, byte[]> { ["doc.txt"] = payload.ToArray() },
            new List<byte[]> { Encoding.UTF8.GetBytes(patched) });

        var report = await EdocValidation.OpenAndValidateAsync(new MemoryStream(zip), SignatureTrustPolicy.CryptographyOnly);
        Assert.False(report.AllSignaturesValid);
        Assert.Contains("Missing payload", report.Signatures[0].Result.Error ?? string.Empty, StringComparison.Ordinal);
        Assert.Contains("/doc.txt", report.Signatures[0].Result.Error ?? string.Empty, StringComparison.Ordinal);
    }

    /// <summary>
    /// Files under <c>META-INF/</c> that do not match manifest/signature naming rules are skipped (no duplicate of
    /// <see cref="Payload_file_present_in_zip_but_not_in_manifest_rejected_on_load"/> — this entry is not a payload path).
    /// </summary>
    [Fact]
    public async Task Opaque_meta_inf_attachment_is_ignored_container_still_validates()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=opaque-meta", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "ok"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-05-11T13:00:00Z"));

        var manifest = new OasisManifest();
        manifest.Add("doc.txt", "text/plain");

        using var ms = new MemoryStream();
        using (var zos = new ZipOutputStream(ms) { IsStreamOwner = false })
        {
            var mt = new ZipEntry("mimetype") { CompressionMethod = CompressionMethod.Stored };
            zos.PutNextEntry(mt);
            var mime = Encoding.UTF8.GetBytes(AsicContainer.MimeType);
            zos.Write(mime, 0, mime.Length);
            zos.CloseEntry();

            var man = new ZipEntry("META-INF/manifest.xml") { CompressionMethod = CompressionMethod.Deflated };
            zos.PutNextEntry(man);
            manifest.Generate().Save(zos);
            zos.CloseEntry();

            var orphan = new ZipEntry("META-INF/opaque-attachment.bin") { CompressionMethod = CompressionMethod.Stored };
            zos.PutNextEntry(orphan);
            var junk = "not-a-signature"u8.ToArray();
            zos.Write(junk, 0, junk.Length);
            zos.CloseEntry();

            var se = new ZipEntry("META-INF/signatures0.xml") { CompressionMethod = CompressionMethod.Deflated };
            zos.PutNextEntry(se);
            var sx = Encoding.UTF8.GetBytes(SerializeSig(sig));
            zos.Write(sx, 0, sx.Length);
            zos.CloseEntry();

            var data = new ZipEntry("doc.txt") { CompressionMethod = CompressionMethod.Deflated };
            zos.PutNextEntry(data);
            zos.Write(payload, 0, payload.Length);
            zos.CloseEntry();
        }

        ms.Position = 0;
        var report = await EdocValidation.OpenAndValidateAsync(ms, SignatureTrustPolicy.CryptographyOnly);
        Assert.True(report.AllSignaturesValid, report.Signatures.ElementAtOrDefault(0)?.Result.Error);
        Assert.Single(report.Edoc.Signatures);
    }

    /// <summary>ASiC-E shell with data + manifest but no <c>META-INF/signatures*.xml</c> (cf. unsigned tooling outputs).</summary>
    [Fact]
    public async Task Mimetype_manifest_payload_without_signature_entries_loads_unsigned_shell()
    {
        var manifest = new OasisManifest();
        manifest.Add("solo.bin", "application/octet-stream");
        var payload = "unsigned-shell"u8.ToArray();

        var zip = ZipTestHelpers.BuildMinimalAsicZip(
            manifest.Generate(),
            new Dictionary<string, byte[]> { ["solo.bin"] = payload.ToArray() },
            Array.Empty<byte[]>());

        var edoc = new Edoc(new MemoryStream(zip));
        Assert.Single(edoc.DataFiles);
        Assert.Equal("solo.bin", edoc.DataFiles.First().Name);
        Assert.Empty(edoc.Signatures);

        var report = await EdocValidation.ValidateSignaturesAsync(edoc, SignatureTrustPolicy.CryptographyOnly);
        Assert.False(report.HasSignatures);
        Assert.False(report.AllSignaturesValid);
    }

    /// <summary>
    /// <see cref="OasisManifest"/> keys are case-sensitive; ZIP entry names may differ only by case — structural validation
    /// uses case-insensitive matching, but attaching declared media-type uses exact dictionary lookup.
    /// </summary>
    [Fact]
    public async Task When_manifest_full_path_casing_differs_from_zip_entry_media_type_from_manifest_is_applied_case_insensitively()
    {
        var manifest = new OasisManifest();
        manifest.Add("DOC.TXT", "application/x-case-test");

        var zip = ZipTestHelpers.BuildMinimalAsicZip(
            manifest.Generate(),
            new Dictionary<string, byte[]> { ["doc.txt"] = "bytes"u8.ToArray() },
            Array.Empty<byte[]>());

        var edoc = new Edoc(new MemoryStream(zip));
        var df = edoc.DataFiles.First();
        Assert.Equal("doc.txt", df.Name);
        Assert.Equal("application/x-case-test", df.MimeType);
    }

    /// <summary>Malformed-looking but single-token media types (e.g. missing subtype slash) still surface as declared.</summary>
    [Fact]
    public async Task Manifest_media_type_without_slash_still_applied_when_paths_match_exactly()
    {
        var manifest = new OasisManifest();
        manifest.Add("note.txt", "textplain");

        var zip = ZipTestHelpers.BuildMinimalAsicZip(
            manifest.Generate(),
            new Dictionary<string, byte[]> { ["note.txt"] = "n"u8.ToArray() },
            Array.Empty<byte[]>());

        var edoc = new Edoc(new MemoryStream(zip));
        Assert.Equal("textplain", edoc.DataFiles.First().MimeType);
    }

    private static string SerializeSig(AsicSignature sig)
    {
        using var s = new MemoryStream();
        sig.WriteTo(s);
        return Encoding.UTF8.GetString(s.ToArray());
    }

    /// <summary>Patches the first <c>ds:Reference</c> whose URI is not an XPointer fragment (detached file digest).</summary>
    private static string PatchFirstDetachedReferenceDigestMethod(string signatureXml, string digestMethodUri)
    {
        var doc = new XmlDocument { PreserveWhitespace = false };
        doc.LoadXml(signatureXml);
        var nsmgr = new XmlNamespaceManager(doc.NameTable);
        nsmgr.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
        var references = doc.SelectNodes("//ds:Reference", nsmgr);
        if (references == null)
        {
            throw new InvalidOperationException("No Reference elements.");
        }

        foreach (XmlElement reference in references)
        {
            var uri = reference.GetAttribute("URI");
            if (uri.StartsWith('#'))
            {
                continue;
            }

            var dm = (XmlElement?)reference.SelectSingleNode("ds:DigestMethod", nsmgr);
            if (dm == null)
            {
                continue;
            }

            dm.SetAttribute("Algorithm", digestMethodUri);
            return doc.OuterXml;
        }

        throw new InvalidOperationException("No detached Reference found.");
    }

    private static string PatchSignedInfoSignatureMethod(string signatureXml, string signatureMethodUri)
    {
        var doc = new XmlDocument { PreserveWhitespace = false };
        doc.LoadXml(signatureXml);
        var nsmgr = new XmlNamespaceManager(doc.NameTable);
        nsmgr.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
        var sm = doc.SelectSingleNode("//ds:SignedInfo/ds:SignatureMethod", nsmgr) as XmlElement
                 ?? throw new InvalidOperationException("SignatureMethod missing.");
        sm.SetAttribute("Algorithm", signatureMethodUri);
        return doc.OuterXml;
    }

    private static string PatchFirstDetachedReferenceUri(string signatureXml, string newUri)
    {
        var doc = new XmlDocument { PreserveWhitespace = false };
        doc.LoadXml(signatureXml);
        var nsmgr = new XmlNamespaceManager(doc.NameTable);
        nsmgr.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
        var references = doc.SelectNodes("//ds:Reference", nsmgr);
        if (references == null)
        {
            throw new InvalidOperationException("No Reference elements.");
        }

        foreach (XmlElement reference in references)
        {
            var uri = reference.GetAttribute("URI");
            if (uri.StartsWith('#'))
            {
                continue;
            }

            reference.SetAttribute("URI", newUri);
            return doc.OuterXml;
        }

        throw new InvalidOperationException("No detached Reference found.");
    }
}
