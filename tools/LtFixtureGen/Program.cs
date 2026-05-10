using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Asic.Xades;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

/// <summary>Regenerates EP-13 synthetic LT fixtures (run from repo root when bytes need refreshing).</summary>
internal static class Program
{
    internal static int Main(string[] args)
    {
        var outDir = args.Length > 0 ? args[0] : Path.Combine(
            FindRepoRoot(),
            "test",
            "eDocLib.Tests",
            "Fixtures",
            "lt");
        Directory.CreateDirectory(outDir);
        var edocPath = Path.Combine(outDir, "synthetic-ocsp-lt.edoc");
        var anchorPath = Path.Combine(outDir, "synthetic-ocsp-lt-anchor.cer");

        var (issuer, leaf, ocspDer) = CreateIssuerLeafAndIssuerSignedOcsp(
            "EP13 Synthetic LT CA",
            "EP13 Synthetic LT Signer");
        using (issuer)
        using (leaf)
        {
            File.WriteAllBytes(anchorPath, issuer.Export(X509ContentType.Cert));

            var payload = "ep13-synthetic-lt-fixture"u8.ToArray();
            var sig = XadesBesSigner.Sign(
                new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
                leaf,
                DateTimeOffset.Parse("2026-05-09T12:00:00Z"));
            XadesBesSigner.AppendUnsignedRevocationValues(sig, [ocspDer], null);

            var edoc = Edoc.CreateNew();
            edoc.AddDataObject(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
            edoc.AddSignature(sig);

            using var zip = new MemoryStream();
            edoc.Save(zip);
            File.WriteAllBytes(edocPath, zip.ToArray());
        }

        Console.WriteLine($"Wrote {edocPath}");
        Console.WriteLine($"Wrote {anchorPath}");
        return 0;
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

    private static (X509Certificate2 Issuer, X509Certificate2 Leaf, byte[] OcspDer) CreateIssuerLeafAndIssuerSignedOcsp(
        string issuerCn,
        string leafCn)
    {
        using var issuerRsa = RSA.Create(2048);
        var issuerReq = new CertificateRequest(
            "CN=" + issuerCn,
            issuerRsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        issuerReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        issuerReq.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, false));
        var issuer = issuerReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(5));

        using var leafRsa = RSA.Create(2048);
        var leafReq = new CertificateRequest(
            "CN=" + leafCn,
            leafRsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        var leafSerial = new byte[8];
        RandomNumberGenerator.Fill(leafSerial);
        var leafPub = leafReq.Create(issuer, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), leafSerial);
        var leaf = leafPub.CopyWithPrivateKey(leafRsa);

        var parser = new X509CertificateParser();
        var issuerBc = parser.ReadCertificate(issuer.RawData);
        var leafBc = parser.ReadCertificate(leaf.RawData);
        var issuerKeyPair = DotNetUtilities.GetKeyPair(issuer.GetRSAPrivateKey()!);

#pragma warning disable CS0618
        var certId = new CertificateID(OiwObjectIdentifiers.IdSha1.Id, issuerBc, leafBc.SerialNumber);
#pragma warning restore CS0618
        var basicGen = new BasicOcspRespGenerator(issuerKeyPair.Public);
        basicGen.AddResponse(certId, null, DateTime.UtcNow, null, null);
        var basic = basicGen.Generate(
            new Asn1SignatureFactory("SHA256WithRSA", issuerKeyPair.Private),
            [issuerBc],
            DateTime.UtcNow);
        var ocspDer = new OCSPRespGenerator().Generate(OcspRespStatus.Successful, basic).GetEncoded();

        return (issuer, leaf, ocspDer);
    }
}
