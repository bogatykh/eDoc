using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Asic.Xades;

/// <summary>
/// Writes synthetic ASiC-E samples (XAdES-BES) for offline regression tests. Run from repo root; defaults to
/// <c>test/eDocLib.Tests/Fixtures/bes/</c>.
/// </summary>
internal static class Program
{
    private static readonly DateTimeOffset SigningTime = DateTimeOffset.Parse("2026-10-15T14:30:00Z");

    internal static int Main(string[] args)
    {
        var outDir = args.Length > 0
            ? args[0]
            : Path.Combine(FindRepoRoot(), "test", "eDocLib.Tests", "Fixtures", "bes");
        Directory.CreateDirectory(outDir);

        using var rsaMain = RSA.Create(2048);
        var reqMain = new CertificateRequest(
            "CN=Bes Synthetic Fixture Signer",
            rsaMain,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using var certMain = reqMain.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-3), DateTimeOffset.UtcNow.AddYears(3));

        using var rsaCo = RSA.Create(2048);
        var reqCo = new CertificateRequest(
            "CN=Bes Synthetic Parallel Co-Signer",
            rsaCo,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using var certCo = reqCo.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-3), DateTimeOffset.UtcNow.AddYears(3));

        using var ecKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var reqEc = new CertificateRequest(
            "CN=Bes Synthetic ECDSA P-256",
            ecKey,
            HashAlgorithmName.SHA256);
        using var certEc = reqEc.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-3), DateTimeOffset.UtcNow.AddYears(3));

        File.WriteAllBytes(Path.Combine(outDir, "synthetic-bes-anchor.cer"), certMain.Export(X509ContentType.Cert));
        File.WriteAllBytes(Path.Combine(outDir, "synthetic-bes-parallel-co-anchor.cer"), certCo.Export(X509ContentType.Cert));
        File.WriteAllBytes(Path.Combine(outDir, "synthetic-bes-ecdsa-p256-anchor.cer"), certEc.Export(X509ContentType.Cert));

        WriteSingle(outDir, certMain);
        WriteMulti(outDir, certMain);
        WriteEmptyPayload(outDir, certMain);
        WriteUnicodePath(outDir, certMain);
        WriteRsaSha384(outDir, certMain);
        WriteEcdsaP256(outDir, certEc);
        WriteParallelDualSignature(outDir, certMain, certCo);

        var singleEdoc = Path.Combine(outDir, "synthetic-bes-single.edoc");
        File.Copy(singleEdoc, Path.Combine(outDir, "synthetic-bes-single.asice"), overwrite: true);
        File.Copy(singleEdoc, Path.Combine(outDir, "synthetic-bes-single.asic"), overwrite: true);

        Console.WriteLine($"Wrote fixtures under {outDir}");
        Console.WriteLine($"Primary RSA anchor: synthetic-bes-anchor.cer");
        return 0;
    }

    private static void WriteSingle(string outDir, X509Certificate2 cert)
    {
        var payload = "bes-fixture-line-1\n"u8.ToArray();
        var dfs = new[]
        {
            new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain"),
        };
        var sig = XadesBesSigner.Sign(dfs, cert, SigningTime, signatureId: "sig-bes-single");

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sig);

        WriteZip(Path.Combine(outDir, "synthetic-bes-single.edoc"), edoc);
    }

    private static void WriteMulti(string outDir, X509Certificate2 cert)
    {
        var a = "bundle-alpha"u8.ToArray();
        var b = "bundle-beta"u8.ToArray();
        var c = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        var dfs = new[]
        {
            new DataFile(new MemoryStream(a.ToArray()), "bundle/a.bin", "application/octet-stream"),
            new DataFile(new MemoryStream(b.ToArray()), "bundle/b.bin", "application/octet-stream"),
            new DataFile(new MemoryStream(c.ToArray()), "marker.raw", "application/octet-stream"),
        };
        var sig = XadesBesSigner.Sign(dfs, cert, SigningTime, signatureId: "sig-bes-multi");

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(a.ToArray()), "bundle/a.bin", "application/octet-stream");
        edoc.AddDataFile(new MemoryStream(b.ToArray()), "bundle/b.bin", "application/octet-stream");
        edoc.AddDataFile(new MemoryStream(c.ToArray()), "marker.raw", "application/octet-stream");
        edoc.AddSignature(sig);

        WriteZip(Path.Combine(outDir, "synthetic-bes-multi.edoc"), edoc);
    }

    private static void WriteEmptyPayload(string outDir, X509Certificate2 cert)
    {
        var empty = Array.Empty<byte>();
        var dfs = new[] { new DataFile(new MemoryStream(empty), "empty.dat", "application/octet-stream") };
        var sig = XadesBesSigner.Sign(dfs, cert, SigningTime, signatureId: "sig-bes-empty");

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(empty), "empty.dat", "application/octet-stream");
        edoc.AddSignature(sig);

        WriteZip(Path.Combine(outDir, "synthetic-bes-empty.edoc"), edoc);
    }

    private static void WriteUnicodePath(string outDir, X509Certificate2 cert)
    {
        var payload = "unicode-path-payload"u8.ToArray();
        var name = "nested/\u9644\u4EF6-sample.bin";
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), name, "application/octet-stream") };
        var sig = XadesBesSigner.Sign(dfs, cert, SigningTime, signatureId: "sig-bes-unicode");

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), name, "application/octet-stream");
        edoc.AddSignature(sig);

        WriteZip(Path.Combine(outDir, "synthetic-bes-unicode-path.edoc"), edoc);
    }

    private static void WriteRsaSha384(string outDir, X509Certificate2 cert)
    {
        var payload = "rsa-sha384-fixture-body\n"u8.ToArray();
        var dfs = new[]
        {
            new DataFile(new MemoryStream(payload.ToArray()), "sha384-doc.txt", "text/plain"),
        };
        var sig = XadesBesSigner.Sign(
            dfs,
            cert,
            SigningTime,
            signatureId: "sig-bes-rsa-sha384",
            rsaDigestPreference: XadesRsaDigestPreference.Sha384);

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "sha384-doc.txt", "text/plain");
        edoc.AddSignature(sig);

        WriteZip(Path.Combine(outDir, "synthetic-bes-rsa-sha384.edoc"), edoc);
    }

    private static void WriteEcdsaP256(string outDir, X509Certificate2 certEc)
    {
        var payload = "ecdsa-p256-fixture-payload"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "ec-note.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, certEc, SigningTime, signatureId: "sig-bes-ecdsa-p256");

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "ec-note.txt", "text/plain");
        edoc.AddSignature(sig);

        WriteZip(Path.Combine(outDir, "synthetic-bes-ecdsa-p256.edoc"), edoc);
    }

    private static void WriteParallelDualSignature(string outDir, X509Certificate2 certA, X509Certificate2 certB)
    {
        var payload = "parallel-shared-body\n"u8.ToArray();
        var dfsA = new[] { new DataFile(new MemoryStream(payload.ToArray()), "shared.txt", "text/plain") };
        var sigA = XadesBesSigner.Sign(dfsA, certA, SigningTime, signatureId: "sig-parallel-a");
        var dfsB = new[] { new DataFile(new MemoryStream(payload.ToArray()), "shared.txt", "text/plain") };
        var sigB = XadesBesSigner.Sign(dfsB, certB, SigningTime, signatureId: "sig-parallel-b");

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "shared.txt", "text/plain");
        edoc.AddSignature(sigA);
        edoc.AddSignature(sigB);

        WriteZip(Path.Combine(outDir, "synthetic-bes-parallel-sigs.edoc"), edoc);
    }

    private static void WriteZip(string path, Edoc edoc)
    {
        using var zip = new MemoryStream();
        edoc.Save(zip);
        File.WriteAllBytes(path, zip.ToArray());
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
