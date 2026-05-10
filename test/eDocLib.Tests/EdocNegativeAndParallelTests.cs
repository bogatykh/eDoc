using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml.Linq;
using eDocLib.Asic.Container;
using eDocLib.Asic.Manifest;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using ICSharpCode.SharpZipLib.Zip;
using Xunit;

namespace eDocLib;

public class EdocNegativeAndParallelTests
{
    [Fact]
    public void N01_corrupted_payload_fails_signature_verification()
    {
        var (zipBytes, _) = CreateSignedOneFileEdoc("hello eDoc"u8.ToArray());
        var corrupted = ZipTestHelpers.CorruptEntryPayload(zipBytes, "doc.txt", xorByte: 0x01);
        var report = EdocValidation.OpenAndValidate(new MemoryStream(corrupted), SignatureTrustPolicy.CryptographyOnly);
        Assert.False(report.AllSignaturesValid);
        Assert.Contains("Digest mismatch", report.Signatures[0].Result.Error ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public void N02_manifest_lists_missing_file_throws_on_read()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=t", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "x"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2024-01-01T00:00:00Z"));

        var manifest = new OasisManifest();
        manifest.Add("doc.txt", "text/plain");
        manifest.Add("ghost.txt", "text/plain");

        var brokenZip = ZipTestHelpers.BuildMinimalAsicZip(
            manifest.Generate(),
            new Dictionary<string, byte[]> { ["doc.txt"] = payload },
            new List<byte[]> { Encoding.UTF8.GetBytes(SerializeSignatureToUtf8(sig)) });

        var ex = Assert.Throws<AsicException>(() => new Edoc(new MemoryStream(brokenZip)));
        Assert.Contains("ghost.txt", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void N03_wrong_first_zip_entry_throws()
    {
        using var ms = new MemoryStream();
        using (var zos = new ZipOutputStream(ms) { IsStreamOwner = false })
        {
            var wrongFirst = new ZipEntry("META-INF/manifest.xml");
            wrongFirst.CompressionMethod = CompressionMethod.Stored;
            zos.PutNextEntry(wrongFirst);
            var manifest = new OasisManifest();
            manifest.Add("doc.txt", "text/plain");
            manifest.Generate().Save(zos);
            zos.CloseEntry();

            var mt = new ZipEntry(ZipTestHelpers.MimeTypeEntryName);
            mt.CompressionMethod = CompressionMethod.Stored;
            zos.PutNextEntry(mt);
            var mimeBytes = Encoding.UTF8.GetBytes(AsicContainer.MimeType);
            zos.Write(mimeBytes, 0, mimeBytes.Length);
            zos.CloseEntry();
        }

        ms.Position = 0;
        var ex = Assert.Throws<AsicException>(() => new Edoc(ms));
        Assert.Contains("First ZIP entry", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void N04_duplicate_data_file_name_in_zip_throws()
    {
        var payload = "a"u8.ToArray();
        var manifest = new OasisManifest();
        manifest.Add("doc.txt", "text/plain");
        var duplicateZip = ZipTestHelpers.BuildZipWithDuplicatePayloadEntry(manifest.Generate(), payload);
        var ex = Assert.Throws<AsicException>(() => new Edoc(new MemoryStream(duplicateZip)));
        Assert.Contains("Duplicate", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void C07_parallel_two_Xades_signatures_both_validate()
    {
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var req1 = new CertificateRequest("CN=s1", rsa1, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var req2 = new CertificateRequest("CN=s2", rsa2, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert1 = req1.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "parallel"u8.ToArray();
        var t = DateTimeOffset.Parse("2024-06-01T10:00:00Z");

        var dfs1 = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig1 = XadesBesSigner.Sign(dfs1, cert1, t, "sig-1", "SignedProperties-1");

        var dfs2 = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig2 = XadesBesSigner.Sign(dfs2, cert2, t, "sig-2", "SignedProperties-2");

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sig1);
        edoc.AddSignature(sig2);

        Assert.Equal(2, edoc.Signatures.Count);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var report = EdocValidation.OpenAndValidate(zip, SignatureTrustPolicy.CryptographyOnly);
        Assert.Equal(2, report.Signatures.Count);
        Assert.True(report.AllSignaturesValid);
        foreach (var s in report.Signatures)
        {
            Assert.True(s.Result.Success, s.Result.Error);
        }

        zip.Position = 0;
        using var za = new ZipArchive(zip, ZipArchiveMode.Read, leaveOpen: true);
        Assert.Equal(2, za.Entries.Count(e => e.FullName.StartsWith("META-INF/signatures", StringComparison.OrdinalIgnoreCase) && e.FullName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)));
    }

    private static (byte[] ZipBytes, X509Certificate2 Cert) CreateSignedOneFileEdoc(byte[] payload)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=t", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2024-01-01T00:00:00Z"));

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sig);

        using var ms = new MemoryStream();
        edoc.Save(ms);
        return (ms.ToArray(), cert);
    }

    private static string SerializeSignatureToUtf8(eDocLib.Asic.Container.AsicSignature sig)
    {
        using var s = new MemoryStream();
        sig.WriteTo(s);
        return Encoding.UTF8.GetString(s.ToArray());
    }
}

internal static class ZipTestHelpers
{
    internal const string MimeTypeEntryName = "mimetype";
    internal const string ManifestZipPath = "META-INF/manifest.xml";

    public static byte[] CorruptEntryPayload(byte[] zipBytes, string entryName, byte xorByte)
    {
        using var input = new MemoryStream(zipBytes);
        using var zis = new ZipInputStream(input) { IsStreamOwner = false };
        using var output = new MemoryStream();
        using var zos = new ZipOutputStream(output) { IsStreamOwner = false };

        while (zis.GetNextEntry() is { } e)
        {
            if (e.IsDirectory)
            {
                continue;
            }

            using var ms = new MemoryStream();
            zis.CopyTo(ms);
            var bytes = ms.ToArray();
            if (string.Equals(e.Name, entryName, StringComparison.OrdinalIgnoreCase) && bytes.Length > 0)
            {
                bytes[0] ^= xorByte;
            }

            var ze = new ZipEntry(e.Name)
            {
                CompressionMethod = e.CompressionMethod,
            };
            zos.PutNextEntry(ze);
            zos.Write(bytes, 0, bytes.Length);
            zos.CloseEntry();
        }

        zos.Finish();
        return output.ToArray();
    }

    /// <summary>mimetype → manifest → each sig XML → payload files (order).</summary>
    public static byte[] BuildMinimalAsicZip(XDocument manifestDoc, IReadOnlyDictionary<string, byte[]> payloadFiles, IReadOnlyList<byte[]> signatureXmlUtf8Blobs)
    {
        using var ms = new MemoryStream();
        using (var zos = new ZipOutputStream(ms) { IsStreamOwner = false })
        {
            var mt = new ZipEntry(MimeTypeEntryName)
            {
                CompressionMethod = CompressionMethod.Stored,
            };
            zos.PutNextEntry(mt);
            var mime = Encoding.UTF8.GetBytes(AsicContainer.MimeType);
            zos.Write(mime, 0, mime.Length);
            zos.CloseEntry();

            var man = new ZipEntry(ManifestZipPath)
            {
                CompressionMethod = CompressionMethod.Deflated,
            };
            zos.PutNextEntry(man);
            manifestDoc.Save(zos);
            zos.CloseEntry();

            for (var i = 0; i < signatureXmlUtf8Blobs.Count; i++)
            {
                var se = new ZipEntry($"META-INF/signatures{i}.xml")
                {
                    CompressionMethod = CompressionMethod.Deflated,
                };
                zos.PutNextEntry(se);
                var xml = signatureXmlUtf8Blobs[i];
                zos.Write(xml, 0, xml.Length);
                zos.CloseEntry();
            }

            foreach (var kv in payloadFiles)
            {
                var de = new ZipEntry(kv.Key)
                {
                    CompressionMethod = CompressionMethod.Deflated,
                };
                zos.PutNextEntry(de);
                zos.Write(kv.Value, 0, kv.Value.Length);
                zos.CloseEntry();
            }
        }

        return ms.ToArray();
    }

    /// <summary>Same layout as <see cref="BuildMinimalAsicZip"/> but writes two ZIP entries with the same signature path (second wins on naive replay — reader processes both in order).</summary>
    internal static byte[] BuildMinimalAsicZipDuplicateSignatureEntry(
        XDocument manifestDoc,
        IReadOnlyDictionary<string, byte[]> payloadFiles,
        byte[] firstSignatureXmlUtf8,
        byte[] secondSignatureXmlUtf8SamePath)
    {
        using var ms = new MemoryStream();
        using (var zos = new ZipOutputStream(ms) { IsStreamOwner = false })
        {
            var mt = new ZipEntry(MimeTypeEntryName)
            {
                CompressionMethod = CompressionMethod.Stored,
            };
            zos.PutNextEntry(mt);
            var mime = Encoding.UTF8.GetBytes(AsicContainer.MimeType);
            zos.Write(mime, 0, mime.Length);
            zos.CloseEntry();

            var man = new ZipEntry(ManifestZipPath)
            {
                CompressionMethod = CompressionMethod.Deflated,
            };
            zos.PutNextEntry(man);
            manifestDoc.Save(zos);
            zos.CloseEntry();

            void WriteSig(byte[] xml)
            {
                var se = new ZipEntry("META-INF/signatures0.xml")
                {
                    CompressionMethod = CompressionMethod.Deflated,
                };
                zos.PutNextEntry(se);
                zos.Write(xml, 0, xml.Length);
                zos.CloseEntry();
            }

            WriteSig(firstSignatureXmlUtf8);
            WriteSig(secondSignatureXmlUtf8SamePath);

            foreach (var kv in payloadFiles)
            {
                var de = new ZipEntry(kv.Key)
                {
                    CompressionMethod = CompressionMethod.Deflated,
                };
                zos.PutNextEntry(de);
                zos.Write(kv.Value, 0, kv.Value.Length);
                zos.CloseEntry();
            }
        }

        return ms.ToArray();
    }

    internal static byte[] BuildMinimalAsicZipRawManifestUtf8(
        byte[] manifestUtf8NoBom,
        IReadOnlyDictionary<string, byte[]> payloadFiles,
        IReadOnlyList<byte[]> signatureXmlUtf8Blobs)
    {
        using var ms = new MemoryStream();
        using (var zos = new ZipOutputStream(ms) { IsStreamOwner = false })
        {
            var mt = new ZipEntry(MimeTypeEntryName)
            {
                CompressionMethod = CompressionMethod.Stored,
            };
            zos.PutNextEntry(mt);
            var mime = Encoding.UTF8.GetBytes(AsicContainer.MimeType);
            zos.Write(mime, 0, mime.Length);
            zos.CloseEntry();

            var man = new ZipEntry(ManifestZipPath)
            {
                CompressionMethod = CompressionMethod.Deflated,
            };
            zos.PutNextEntry(man);
            zos.Write(manifestUtf8NoBom, 0, manifestUtf8NoBom.Length);
            zos.CloseEntry();

            for (var i = 0; i < signatureXmlUtf8Blobs.Count; i++)
            {
                var se = new ZipEntry($"META-INF/signatures{i}.xml")
                {
                    CompressionMethod = CompressionMethod.Deflated,
                };
                zos.PutNextEntry(se);
                var xml = signatureXmlUtf8Blobs[i];
                zos.Write(xml, 0, xml.Length);
                zos.CloseEntry();
            }

            foreach (var kv in payloadFiles)
            {
                var de = new ZipEntry(kv.Key)
                {
                    CompressionMethod = CompressionMethod.Deflated,
                };
                zos.PutNextEntry(de);
                zos.Write(kv.Value, 0, kv.Value.Length);
                zos.CloseEntry();
            }
        }

        return ms.ToArray();
    }

    public static byte[] BuildZipWithDuplicatePayloadEntry(XDocument manifestDoc, byte[] payload)
    {
        using var ms = new MemoryStream();
        using (var zos = new ZipOutputStream(ms) { IsStreamOwner = false })
        {
            var mt = new ZipEntry(MimeTypeEntryName)
            {
                CompressionMethod = CompressionMethod.Stored,
            };
            zos.PutNextEntry(mt);
            var mime = Encoding.UTF8.GetBytes(AsicContainer.MimeType);
            zos.Write(mime, 0, mime.Length);
            zos.CloseEntry();

            var man = new ZipEntry(ManifestZipPath)
            {
                CompressionMethod = CompressionMethod.Deflated,
            };
            zos.PutNextEntry(man);
            manifestDoc.Save(zos);
            zos.CloseEntry();

            for (var i = 0; i < 2; i++)
            {
                var de = new ZipEntry("doc.txt")
                {
                    CompressionMethod = CompressionMethod.Deflated,
                };
                zos.PutNextEntry(de);
                zos.Write(payload, 0, payload.Length);
                zos.CloseEntry();
            }
        }

        return ms.ToArray();
    }
}
