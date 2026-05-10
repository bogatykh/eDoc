using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using eDocLib;
using eDocLib.Asic.Container;
using eDocLib.Asic.Manifest;
using eDocLib.Asic.Xades;
using ICSharpCode.SharpZipLib.Zip;

/// <summary>
/// Writes deliberately broken ASiC-E ZIPs for negative tests. Defaults to
/// <c>test/eDocLib.Tests/Fixtures/bes-invalid/</c>.
/// </summary>
internal static class Program
{
    private const string MimeTypeEntryName = "mimetype";
    private const string ManifestZipPath = "META-INF/manifest.xml";
    private const string DataEntryName = "payload.bin";
    private const string OrphanPayloadEntryName = "orphan-extra.bin";
    /// <summary>ASiC-S media type — wrong for an ASiC-E container (confusion regression).</summary>
    private const string AsicSMimeTypeText = "application/vnd.etsi.asic-s+zip";
    private const string XmlDsigNamespaceUrl = "http://www.w3.org/2000/09/xmldsig#";
    private static readonly DateTimeOffset SigningTime = DateTimeOffset.Parse("2026-11-01T12:00:00Z");

    internal static int Main(string[] args)
    {
        var outDir = args.Length > 0
            ? args[0]
            : Path.Combine(FindRepoRoot(), "test", "eDocLib.Tests", "Fixtures", "bes-invalid");
        Directory.CreateDirectory(outDir);

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            "CN=Invalid Fixture Synthetic Signer",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(2));

        var payload = "invalid-fixture-base-payload\n"u8.ToArray();
        var validZip = BuildValidSignedZip(payload, cert);

        File.WriteAllBytes(Path.Combine(outDir, "invalid-digest-mismatch.edoc"), CorruptEntryPayload(validZip, DataEntryName, 0x01));

        var truncatedLen = Math.Max(512, validZip.Length - 900);
        File.WriteAllBytes(Path.Combine(outDir, "invalid-truncated-zip.edoc"), validZip.AsSpan(0, truncatedLen).ToArray());

        File.WriteAllBytes(Path.Combine(outDir, "invalid-wrong-first-entry.edoc"), BuildWrongFirstEntryZip(payload, cert));
        File.WriteAllBytes(Path.Combine(outDir, "invalid-manifest-ghost-file.edoc"), BuildGhostManifestZip(payload, cert));
        File.WriteAllBytes(Path.Combine(outDir, "invalid-duplicate-payload-name.edoc"), BuildDuplicatePayloadZip(payload));
        File.WriteAllBytes(Path.Combine(outDir, "invalid-mimetype-content.edoc"), BuildWrongMimeContentZip(payload, cert));

        File.WriteAllBytes(Path.Combine(outDir, "invalid-two-mimetype-entries.edoc"), BuildSecondMimetypeOverwritesWithBadContent(payload, cert));
        File.WriteAllBytes(Path.Combine(outDir, "invalid-missing-manifest.edoc"), BuildMissingManifestZip(payload, cert));
        File.WriteAllBytes(Path.Combine(outDir, "invalid-signature-uri-mismatch.edoc"), BuildSignatureUriMismatchZip(payload, cert));

        File.WriteAllBytes(Path.Combine(outDir, "invalid-mimetype-asic-s-body.edoc"), BuildMimeTypeAsicSBodyZip(payload, cert));
        File.WriteAllBytes(Path.Combine(outDir, "invalid-orphan-payload-not-in-manifest.edoc"), BuildOrphanPayloadNotInManifestZip(payload, cert));
        File.WriteAllBytes(Path.Combine(outDir, "invalid-parallel-second-signature-corrupt.edoc"), BuildParallelSecondSignatureCorruptZip(payload, cert));

        Console.WriteLine($"Wrote invalid fixtures under {outDir}");
        return 0;
    }

    private static byte[] BuildValidSignedZip(byte[] payload, X509Certificate2 cert)
    {
        var dfs = new[]
        {
            new DataFile(new MemoryStream(payload.ToArray()), DataEntryName, "application/octet-stream"),
        };
        var sig = XadesBesSigner.Sign(dfs, cert, SigningTime, signatureId: "sig-invalid-base");

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), DataEntryName, "application/octet-stream");
        edoc.AddSignature(sig);

        using var ms = new MemoryStream();
        edoc.Save(ms);
        return ms.ToArray();
    }

    private static byte[] SerializeSignatureUtf8(AsicSignature sig)
    {
        using var s = new MemoryStream();
        sig.WriteTo(s);
        return s.ToArray();
    }

    private static byte[] BuildWrongFirstEntryZip(byte[] payload, X509Certificate2 cert)
    {
        var dfs = new[]
        {
            new DataFile(new MemoryStream(payload.ToArray()), DataEntryName, "application/octet-stream"),
        };
        var sig = XadesBesSigner.Sign(dfs, cert, SigningTime, signatureId: "sig-invalid-base");
        var sigXml = SerializeSignatureUtf8(sig);

        using var ms = new MemoryStream();
        using (var zos = new ZipOutputStream(ms) { IsStreamOwner = false })
        {
            var manifest = new OasisManifest();
            manifest.Add(DataEntryName, "application/octet-stream");
            var manEntry = new ZipEntry(ManifestZipPath)
            {
                CompressionMethod = CompressionMethod.Deflated,
            };
            zos.PutNextEntry(manEntry);
            manifest.Generate().Save(zos);
            zos.CloseEntry();

            var mt = new ZipEntry(MimeTypeEntryName)
            {
                CompressionMethod = CompressionMethod.Stored,
            };
            zos.PutNextEntry(mt);
            var mimeBytes = Encoding.UTF8.GetBytes(AsicContainer.MimeType);
            zos.Write(mimeBytes, 0, mimeBytes.Length);
            zos.CloseEntry();

            var se = new ZipEntry($"META-INF/signatures0.xml")
            {
                CompressionMethod = CompressionMethod.Deflated,
            };
            zos.PutNextEntry(se);
            zos.Write(sigXml, 0, sigXml.Length);
            zos.CloseEntry();

            var data = new ZipEntry(DataEntryName)
            {
                CompressionMethod = CompressionMethod.Deflated,
            };
            zos.PutNextEntry(data);
            zos.Write(payload, 0, payload.Length);
            zos.CloseEntry();
        }

        return ms.ToArray();
    }

    private static byte[] BuildGhostManifestZip(byte[] payload, X509Certificate2 cert)
    {
        var dfs = new[]
        {
            new DataFile(new MemoryStream(payload.ToArray()), DataEntryName, "application/octet-stream"),
        };
        var sig = XadesBesSigner.Sign(dfs, cert, SigningTime, signatureId: "sig-invalid-base");
        var sigXml = SerializeSignatureUtf8(sig);

        var manifest = new OasisManifest();
        manifest.Add(DataEntryName, "application/octet-stream");
        manifest.Add("ghost-not-in-zip.dat", "application/octet-stream");

        return BuildMinimalAsicZip(manifest.Generate(), new Dictionary<string, byte[]> { [DataEntryName] = payload }, new List<byte[]> { sigXml });
    }

    private static byte[] BuildDuplicatePayloadZip(byte[] payload)
    {
        var manifest = new OasisManifest();
        manifest.Add("doc.txt", "text/plain");

        using var ms = new MemoryStream();
        using (var zos = new ZipOutputStream(ms) { IsStreamOwner = false })
        {
            var mt = new ZipEntry(MimeTypeEntryName)
            {
                CompressionMethod = CompressionMethod.Stored,
            };
            zos.PutNextEntry(mt);
            var mimeBytes = Encoding.UTF8.GetBytes(AsicContainer.MimeType);
            zos.Write(mimeBytes, 0, mimeBytes.Length);
            zos.CloseEntry();

            var man = new ZipEntry(ManifestZipPath)
            {
                CompressionMethod = CompressionMethod.Deflated,
            };
            zos.PutNextEntry(man);
            manifest.Generate().Save(zos);
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

    /// <summary>First <c>mimetype</c> entry is stored but declares ASiC-S instead of ASiC-E.</summary>
    private static byte[] BuildMimeTypeAsicSBodyZip(byte[] payload, X509Certificate2 cert)
    {
        var dfs = new[]
        {
            new DataFile(new MemoryStream(payload.ToArray()), DataEntryName, "application/octet-stream"),
        };
        var sig = XadesBesSigner.Sign(dfs, cert, SigningTime, signatureId: "sig-invalid-base");
        var sigXml = SerializeSignatureUtf8(sig);

        using var ms = new MemoryStream();
        using (var zos = new ZipOutputStream(ms) { IsStreamOwner = false })
        {
            var mt = new ZipEntry(MimeTypeEntryName)
            {
                CompressionMethod = CompressionMethod.Stored,
            };
            zos.PutNextEntry(mt);
            var wrong = Encoding.UTF8.GetBytes(AsicSMimeTypeText);
            zos.Write(wrong, 0, wrong.Length);
            zos.CloseEntry();

            var manifest = new OasisManifest();
            manifest.Add(DataEntryName, "application/octet-stream");
            var man = new ZipEntry(ManifestZipPath)
            {
                CompressionMethod = CompressionMethod.Deflated,
            };
            zos.PutNextEntry(man);
            manifest.Generate().Save(zos);
            zos.CloseEntry();

            var se = new ZipEntry("META-INF/signatures0.xml")
            {
                CompressionMethod = CompressionMethod.Deflated,
            };
            zos.PutNextEntry(se);
            zos.Write(sigXml, 0, sigXml.Length);
            zos.CloseEntry();

            var data = new ZipEntry(DataEntryName)
            {
                CompressionMethod = CompressionMethod.Deflated,
            };
            zos.PutNextEntry(data);
            zos.Write(payload, 0, payload.Length);
            zos.CloseEntry();
        }

        return ms.ToArray();
    }

    /// <summary>ZIP contains a payload entry not listed in OASIS manifest (reader requires manifest ↔ payload).</summary>
    private static byte[] BuildOrphanPayloadNotInManifestZip(byte[] payload, X509Certificate2 cert)
    {
        var dfs = new[]
        {
            new DataFile(new MemoryStream(payload.ToArray()), DataEntryName, "application/octet-stream"),
        };
        var sig = XadesBesSigner.Sign(dfs, cert, SigningTime, signatureId: "sig-invalid-base");
        var sigXml = SerializeSignatureUtf8(sig);

        var manifest = new OasisManifest();
        manifest.Add(DataEntryName, "application/octet-stream");

        using var ms = new MemoryStream();
        using (var zos = new ZipOutputStream(ms) { IsStreamOwner = false })
        {
            var mt = new ZipEntry(MimeTypeEntryName)
            {
                CompressionMethod = CompressionMethod.Stored,
            };
            zos.PutNextEntry(mt);
            var mimeBytes = Encoding.UTF8.GetBytes(AsicContainer.MimeType);
            zos.Write(mimeBytes, 0, mimeBytes.Length);
            zos.CloseEntry();

            var man = new ZipEntry(ManifestZipPath)
            {
                CompressionMethod = CompressionMethod.Deflated,
            };
            zos.PutNextEntry(man);
            manifest.Generate().Save(zos);
            zos.CloseEntry();

            var se = new ZipEntry("META-INF/signatures0.xml")
            {
                CompressionMethod = CompressionMethod.Deflated,
            };
            zos.PutNextEntry(se);
            zos.Write(sigXml, 0, sigXml.Length);
            zos.CloseEntry();

            var data = new ZipEntry(DataEntryName)
            {
                CompressionMethod = CompressionMethod.Deflated,
            };
            zos.PutNextEntry(data);
            zos.Write(payload, 0, payload.Length);
            zos.CloseEntry();

            var orphanPayload = "not-in-manifest"u8.ToArray();
            var orphan = new ZipEntry(OrphanPayloadEntryName)
            {
                CompressionMethod = CompressionMethod.Deflated,
            };
            zos.PutNextEntry(orphan);
            zos.Write(orphanPayload, 0, orphanPayload.Length);
            zos.CloseEntry();
        }

        return ms.ToArray();
    }

    /// <summary>Two parallel signatures over the same payload; second file has a corrupted <c>ds:SignatureValue</c>.</summary>
    private static byte[] BuildParallelSecondSignatureCorruptZip(byte[] payload, X509Certificate2 cert)
    {
        var dfs = new[]
        {
            new DataFile(new MemoryStream(payload.ToArray()), DataEntryName, "application/octet-stream"),
        };
        var sig = XadesBesSigner.Sign(dfs, cert, SigningTime, signatureId: "sig-invalid-base");
        var sigGood = SerializeSignatureUtf8(sig);
        var sigBad = MutateSignatureValueFirstOctet(sigGood);

        var manifest = new OasisManifest();
        manifest.Add(DataEntryName, "application/octet-stream");

        return BuildMinimalAsicZip(
            manifest.Generate(),
            new Dictionary<string, byte[]> { [DataEntryName] = payload },
            new List<byte[]> { sigGood, sigBad });
    }

    private static byte[] MutateSignatureValueFirstOctet(ReadOnlySpan<byte> sigXmlUtf8)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        using (var s = new MemoryStream(sigXmlUtf8.ToArray()))
        {
            doc.Load(s);
        }

        if (doc.GetElementsByTagName("SignatureValue", XmlDsigNamespaceUrl).Item(0) is not XmlElement sigVal)
        {
            throw new InvalidOperationException("ds:SignatureValue not found.");
        }

        var octets = Convert.FromBase64String(sigVal.InnerText.Trim());
        octets[0] ^= 0x5A;
        sigVal.InnerText = Convert.ToBase64String(octets);

        using var ms = new MemoryStream();
        using (var w = XmlWriter.Create(
                   ms,
                   new XmlWriterSettings
                   {
                       Encoding = new UTF8Encoding(false),
                       OmitXmlDeclaration = false,
                   }))
        {
            doc.Save(w);
        }

        return ms.ToArray();
    }

    private static byte[] BuildWrongMimeContentZip(byte[] payload, X509Certificate2 cert)
    {
        var dfs = new[]
        {
            new DataFile(new MemoryStream(payload.ToArray()), DataEntryName, "application/octet-stream"),
        };
        var sig = XadesBesSigner.Sign(dfs, cert, SigningTime, signatureId: "sig-invalid-base");
        var sigXml = SerializeSignatureUtf8(sig);

        using var ms = new MemoryStream();
        using (var zos = new ZipOutputStream(ms) { IsStreamOwner = false })
        {
            var mt = new ZipEntry(MimeTypeEntryName)
            {
                CompressionMethod = CompressionMethod.Stored,
            };
            zos.PutNextEntry(mt);
            var wrong = Encoding.UTF8.GetBytes("application/vnd.invalid-not-asic");
            zos.Write(wrong, 0, wrong.Length);
            zos.CloseEntry();

            var manifest = new OasisManifest();
            manifest.Add(DataEntryName, "application/octet-stream");
            var man = new ZipEntry(ManifestZipPath)
            {
                CompressionMethod = CompressionMethod.Deflated,
            };
            zos.PutNextEntry(man);
            manifest.Generate().Save(zos);
            zos.CloseEntry();

            var se = new ZipEntry("META-INF/signatures0.xml")
            {
                CompressionMethod = CompressionMethod.Deflated,
            };
            zos.PutNextEntry(se);
            zos.Write(sigXml, 0, sigXml.Length);
            zos.CloseEntry();

            var data = new ZipEntry(DataEntryName)
            {
                CompressionMethod = CompressionMethod.Deflated,
            };
            zos.PutNextEntry(data);
            zos.Write(payload, 0, payload.Length);
            zos.CloseEntry();
        }

        return ms.ToArray();
    }

    /// <summary>
    /// Degenerate ASiC-E: two ZIP entries named <c>mimetype</c> before the manifest; the second body overwrites
    /// the parsed MIME string and fails validation (distinct from <see cref="BuildWrongMimeContentZip"/> where the first entry is wrong).
    /// </summary>
    private static byte[] BuildSecondMimetypeOverwritesWithBadContent(byte[] payload, X509Certificate2 cert)
    {
        var dfs = new[]
        {
            new DataFile(new MemoryStream(payload.ToArray()), DataEntryName, "application/octet-stream"),
        };
        var sig = XadesBesSigner.Sign(dfs, cert, SigningTime, signatureId: "sig-invalid-base");
        var sigXml = SerializeSignatureUtf8(sig);

        using var ms = new MemoryStream();
        using (var zos = new ZipOutputStream(ms) { IsStreamOwner = false })
        {
            WriteMimeStored(zos, Encoding.UTF8.GetBytes(AsicContainer.MimeType));
            WriteMimeStored(zos, Encoding.UTF8.GetBytes("application/vnd.etsi.asic-s+zip"));

            var manifest = new OasisManifest();
            manifest.Add(DataEntryName, "application/octet-stream");
            var man = new ZipEntry(ManifestZipPath)
            {
                CompressionMethod = CompressionMethod.Deflated,
            };
            zos.PutNextEntry(man);
            manifest.Generate().Save(zos);
            zos.CloseEntry();

            var se = new ZipEntry("META-INF/signatures0.xml")
            {
                CompressionMethod = CompressionMethod.Deflated,
            };
            zos.PutNextEntry(se);
            zos.Write(sigXml, 0, sigXml.Length);
            zos.CloseEntry();

            var data = new ZipEntry(DataEntryName)
            {
                CompressionMethod = CompressionMethod.Deflated,
            };
            zos.PutNextEntry(data);
            zos.Write(payload, 0, payload.Length);
            zos.CloseEntry();
        }

        return ms.ToArray();
    }

    private static void WriteMimeStored(ZipOutputStream zos, byte[] body)
    {
        var mt = new ZipEntry(MimeTypeEntryName)
        {
            CompressionMethod = CompressionMethod.Stored,
        };
        zos.PutNextEntry(mt);
        zos.Write(body, 0, body.Length);
        zos.CloseEntry();
    }

    private static byte[] BuildMissingManifestZip(byte[] payload, X509Certificate2 cert)
    {
        var dfs = new[]
        {
            new DataFile(new MemoryStream(payload.ToArray()), DataEntryName, "application/octet-stream"),
        };
        var sig = XadesBesSigner.Sign(dfs, cert, SigningTime, signatureId: "sig-invalid-base");
        var sigXml = SerializeSignatureUtf8(sig);

        using var ms = new MemoryStream();
        using (var zos = new ZipOutputStream(ms) { IsStreamOwner = false })
        {
            WriteMimeStored(zos, Encoding.UTF8.GetBytes(AsicContainer.MimeType));

            var se = new ZipEntry("META-INF/signatures0.xml")
            {
                CompressionMethod = CompressionMethod.Deflated,
            };
            zos.PutNextEntry(se);
            zos.Write(sigXml, 0, sigXml.Length);
            zos.CloseEntry();

            var data = new ZipEntry(DataEntryName)
            {
                CompressionMethod = CompressionMethod.Deflated,
            };
            zos.PutNextEntry(data);
            zos.Write(payload, 0, payload.Length);
            zos.CloseEntry();
        }

        return ms.ToArray();
    }

    /// <summary>
    /// Manifest and ZIP list <c>payload.bin</c>, but the XAdES references were produced for a different relative URI (signature digest targets <c>wrong-uri.bin</c>).
    /// </summary>
    private static byte[] BuildSignatureUriMismatchZip(byte[] payload, X509Certificate2 cert)
    {
        const string signedRelativeUri = "wrong-uri.bin";

        var dfs = new[]
        {
            new DataFile(new MemoryStream(payload.ToArray()), signedRelativeUri, "application/octet-stream"),
        };
        var sig = XadesBesSigner.Sign(dfs, cert, SigningTime, signatureId: "sig-invalid-base");
        var sigXml = SerializeSignatureUtf8(sig);

        var manifest = new OasisManifest();
        manifest.Add(DataEntryName, "application/octet-stream");

        return BuildMinimalAsicZip(
            manifest.Generate(),
            new Dictionary<string, byte[]> { [DataEntryName] = payload },
            new List<byte[]> { sigXml });
    }

    private static byte[] BuildMinimalAsicZip(
        XDocument manifestDoc,
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

    private static byte[] CorruptEntryPayload(byte[] zipBytes, string entryName, byte xorByte)
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

            using var buf = new MemoryStream();
            zis.CopyTo(buf);
            var bytes = buf.ToArray();
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

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "eDocLib.sln")))
            {
                return dir.FullName;
            }

            dir = dir.Parent;
        }

        throw new InvalidOperationException("Could not locate eDocLib.sln above the output directory.");
    }
}
