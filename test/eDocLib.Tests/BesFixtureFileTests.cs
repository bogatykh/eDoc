using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Asic.Container;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary>Loads committed ASiC-E files from <c>Fixtures/bes/</c> (see <c>tools/BesEdocFixtureGen</c>).</summary>
public class BesFixtureFileTests
{
    private static string BesFixturePath(string name) =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "bes", name);

    private const string MissingHint = "Missing fixture; regenerate: dotnet run --project tools/BesEdocFixtureGen/BesEdocFixtureGen.csproj";

    [Fact]
    public void Single_edoc_file_open_validate_and_payload_matches_expected_bytes()
    {
        var path = BesFixturePath("synthetic-bes-single.edoc");
        Assert.True(File.Exists(path), MissingHint);

        using var fs = File.OpenRead(path);
        var report = EdocValidation.OpenAndValidate(fs, SignatureTrustPolicy.CryptographyOnly);
        Assert.True(report.AllSignaturesValid, report.Signatures.ElementAtOrDefault(0)?.Result.Error);
        Assert.Single(report.Edoc.DataFiles);

        var df = report.Edoc.DataFiles.First();
        Assert.Equal("doc.txt", df.Name);
        var bytes = ReadPayloadBytes(df);
        Assert.Equal("bes-fixture-line-1\n"u8.ToArray(), bytes);
    }

    [Fact]
    public void Asice_extension_same_zip_bytes_as_edoc_validates()
    {
        var edocPath = BesFixturePath("synthetic-bes-single.edoc");
        var asicePath = BesFixturePath("synthetic-bes-single.asice");
        Assert.True(File.Exists(edocPath), MissingHint);
        Assert.True(File.Exists(asicePath), MissingHint);

        var a = File.ReadAllBytes(edocPath);
        var b = File.ReadAllBytes(asicePath);
        Assert.Equal(a, b);

        using var fs = File.OpenRead(asicePath);
        var report = EdocValidation.OpenAndValidate(fs, SignatureTrustPolicy.CryptographyOnly);
        Assert.True(report.AllSignaturesValid, report.Signatures.ElementAtOrDefault(0)?.Result.Error);
    }

    [Fact]
    public void Asic_extension_same_zip_bytes_as_edoc()
    {
        var edocPath = BesFixturePath("synthetic-bes-single.edoc");
        var asicPath = BesFixturePath("synthetic-bes-single.asic");
        Assert.True(File.Exists(edocPath), MissingHint);
        Assert.True(File.Exists(asicPath), MissingHint);
        Assert.Equal(File.ReadAllBytes(edocPath), File.ReadAllBytes(asicPath));
    }

    [Fact]
    public void Rsa_sha384_fixture_uses_sha384_digest_uri_and_validates()
    {
        var path = BesFixturePath("synthetic-bes-rsa-sha384.edoc");
        Assert.True(File.Exists(path), MissingHint);

        using var fs = File.OpenRead(path);
        var report = EdocValidation.OpenAndValidate(fs, SignatureTrustPolicy.CryptographyOnly);
        Assert.True(report.AllSignaturesValid, report.Signatures.ElementAtOrDefault(0)?.Result.Error);

        var xs = Assert.IsType<AsicSignature>(report.Edoc.Signatures.ElementAt(0));
        Assert.Equal(XadesSignatureAlgorithms.RsaWithSha384, xs.SignatureMethod);

        var df = Assert.Single(report.Edoc.DataFiles);
        Assert.Equal("sha384-doc.txt", df.Name);
        Assert.Equal("rsa-sha384-fixture-body\n"u8.ToArray(), ReadPayloadBytes(df));
    }

    [Fact]
    public void Ecdsa_p256_fixture_validates_against_bundled_ecdsa_anchor()
    {
        var edocPath = BesFixturePath("synthetic-bes-ecdsa-p256.edoc");
        var anchorPath = BesFixturePath("synthetic-bes-ecdsa-p256-anchor.cer");
        Assert.True(File.Exists(edocPath), MissingHint);
        Assert.True(File.Exists(anchorPath), MissingHint);

        using var anchor = new X509Certificate2(anchorPath);
        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = true,
            RevocationMode = X509RevocationMode.NoCheck,
            CustomTrustAnchors = new X509Certificate2Collection(anchor),
        };

        using var fs = File.OpenRead(edocPath);
        var report = EdocValidation.OpenAndValidate(fs, policy);
        Assert.True(report.AllSignaturesValid, report.Signatures.ElementAtOrDefault(0)?.Result.Error);
        var xs = Assert.IsType<AsicSignature>(report.Edoc.Signatures.ElementAt(0));
        Assert.Equal(XadesSignatureAlgorithms.EcdsaWithSha256, xs.SignatureMethod);
        Assert.True(report.Signatures[0].Result.CertificateChainValid);
    }

    [Fact]
    public void Two_parallel_signatures_on_disk_both_valid_with_co_signer_anchor()
    {
        var path = BesFixturePath("synthetic-bes-parallel-sigs.edoc");
        var anchorA = BesFixturePath("synthetic-bes-anchor.cer");
        var anchorB = BesFixturePath("synthetic-bes-parallel-co-anchor.cer");
        Assert.True(File.Exists(path), MissingHint);
        Assert.True(File.Exists(anchorA), MissingHint);
        Assert.True(File.Exists(anchorB), MissingHint);

        using var a = new X509Certificate2(anchorA);
        using var b = new X509Certificate2(anchorB);
        var anchors = new X509Certificate2Collection { a, b };
        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = true,
            RevocationMode = X509RevocationMode.NoCheck,
            CustomTrustAnchors = anchors,
        };

        using var fs = File.OpenRead(path);
        var report = EdocValidation.OpenAndValidate(fs, policy);
        Assert.Equal(2, report.Signatures.Count);
        Assert.True(report.AllSignaturesValid, string.Join("; ", report.Signatures.Select(s => s.Result.Error)));
        Assert.All(report.Signatures, s => Assert.True(s.Result.CertificateChainValid));
        Assert.Equal("parallel-shared-body\n"u8.ToArray(), ReadPayloadBytes(report.Edoc.DataFiles.First()));
    }

    [Fact]
    public void Multi_file_fixture_open_validate_and_named_entries_match()
    {
        var path = BesFixturePath("synthetic-bes-multi.edoc");
        Assert.True(File.Exists(path), MissingHint);

        using var fs = File.OpenRead(path);
        var report = EdocValidation.OpenAndValidate(fs, SignatureTrustPolicy.CryptographyOnly);
        Assert.True(report.AllSignaturesValid, report.Signatures.ElementAtOrDefault(0)?.Result.Error);
        Assert.Equal(3, report.Edoc.DataFiles.Count);

        var map = report.Edoc.DataFiles.ToDictionary(d => d.Name, d => ReadPayloadBytes(d), StringComparer.Ordinal);
        Assert.Equal("bundle-alpha"u8.ToArray(), map["bundle/a.bin"]);
        Assert.Equal("bundle-beta"u8.ToArray(), map["bundle/b.bin"]);
        Assert.Equal(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }, map["marker.raw"]);
    }

    [Fact]
    public void Empty_payload_fixture_validates_and_reads_zero_bytes()
    {
        var path = BesFixturePath("synthetic-bes-empty.edoc");
        Assert.True(File.Exists(path), MissingHint);

        using var fs = File.OpenRead(path);
        var report = EdocValidation.OpenAndValidate(fs, SignatureTrustPolicy.CryptographyOnly);
        Assert.True(report.AllSignaturesValid, report.Signatures.ElementAtOrDefault(0)?.Result.Error);
        var df = Assert.Single(report.Edoc.DataFiles);
        Assert.Equal("empty.dat", df.Name);
        Assert.Empty(ReadPayloadBytes(df));
    }

    [Fact]
    public void Unicode_relative_path_fixture_round_trips_name_and_payload()
    {
        var path = BesFixturePath("synthetic-bes-unicode-path.edoc");
        Assert.True(File.Exists(path), MissingHint);

        var expectedName = "nested/\u9644\u4EF6-sample.bin";
        var expectedPayload = "unicode-path-payload"u8.ToArray();

        using var fs = File.OpenRead(path);
        var report = EdocValidation.OpenAndValidate(fs, SignatureTrustPolicy.CryptographyOnly);
        Assert.True(report.AllSignaturesValid, report.Signatures.ElementAtOrDefault(0)?.Result.Error);
        var df = Assert.Single(report.Edoc.DataFiles);
        Assert.Equal(expectedName, df.Name);
        Assert.Equal(expectedPayload, ReadPayloadBytes(df));
    }

    [Fact]
    public void Anchor_cert_validates_signing_chain_when_policy_requires_pkix()
    {
        var edocPath = BesFixturePath("synthetic-bes-single.edoc");
        var anchorPath = BesFixturePath("synthetic-bes-anchor.cer");
        Assert.True(File.Exists(edocPath), MissingHint);
        Assert.True(File.Exists(anchorPath), MissingHint);

        using var anchor = new X509Certificate2(anchorPath);
        using var fs = File.OpenRead(edocPath);
        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = true,
            RevocationMode = X509RevocationMode.NoCheck,
            CustomTrustAnchors = new X509Certificate2Collection(anchor),
        };

        var report = EdocValidation.OpenAndValidate(fs, policy);
        Assert.True(report.AllSignaturesValid, report.Signatures.ElementAtOrDefault(0)?.Result.Error);
        Assert.True(report.Signatures[0].Result.CertificateChainValid);
    }

    private static byte[] ReadPayloadBytes(IDataFile df)
    {
        if (df.Stream.CanSeek)
        {
            df.Stream.Position = 0;
        }

        using var ms = new MemoryStream();
        df.Stream.CopyTo(ms);
        return ms.ToArray();
    }
}
