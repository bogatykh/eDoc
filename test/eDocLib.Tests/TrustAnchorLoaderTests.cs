using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib.Trust;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// Coverage for <see cref="TrustAnchorLoader"/>: PEM (in-memory and file) and PKCS#12 import paths,
/// plus the silent-skip behaviour for unrelated PEM labels (a foot-gun a host might trip over when
/// pointing the loader at a file that happens to also carry private keys).
/// </summary>
public class TrustAnchorLoaderTests
{
    [Fact]
    public void FromPem_loads_single_certificate_block()
    {
        using var cert = CreateCert("CN=trust-anchor-1");
        var pem = ExportPem(cert);
        var coll = TrustAnchorLoader.FromPem(pem);

        Assert.Single(coll);
        Assert.Equal(cert.Subject, coll[0].Subject);
    }

    [Fact]
    public void FromPem_loads_multiple_certificate_blocks_in_order()
    {
        using var a = CreateCert("CN=anchor-a");
        using var b = CreateCert("CN=anchor-b");
        using var c = CreateCert("CN=anchor-c");
        var pem = ExportPem(a) + "\n" + ExportPem(b) + "\n" + ExportPem(c);
        var coll = TrustAnchorLoader.FromPem(pem);

        Assert.Equal(3, coll.Count);
        Assert.Equal(new[] { a.Subject, b.Subject, c.Subject },
            coll.OfType<X509Certificate2>().Select(c => c.Subject).ToArray());
    }

    [Fact]
    public void FromPem_silently_ignores_non_certificate_blocks()
    {
        // Documents the behaviour: only CERTIFICATE-labelled blocks are imported. A bundle containing
        // PRIVATE KEY blocks does NOT raise — but only certificates land in the trust anchor collection.
        using var cert = CreateCert("CN=mixed-bundle");
        var pem = "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAuQ==\n-----END PRIVATE KEY-----\n"
            + ExportPem(cert);
        var coll = TrustAnchorLoader.FromPem(pem);

        Assert.Single(coll);
        Assert.Equal(cert.Subject, coll[0].Subject);
    }

    [Fact]
    public void FromPem_returns_empty_for_text_without_certificate_blocks()
    {
        // Caller-visible signal that no anchors were found: empty collection, no exception.
        var coll = TrustAnchorLoader.FromPem("# no certificates here\n");
        Assert.Empty(coll);
    }

    [Fact]
    public void FromPem_returns_empty_for_blank_input()
    {
        var coll = TrustAnchorLoader.FromPem(ReadOnlySpan<char>.Empty);
        Assert.Empty(coll);
    }

    [Fact]
    public void FromPem_invalid_pem_inside_certificate_block_throws_or_skips_consistently()
    {
        // Documents the .NET 8 behaviour: X509Certificate2Collection.ImportFromPem treats CERTIFICATE blocks
        // with malformed base64 either by throwing CryptographicException OR by silently skipping (the precise
        // contract is platform-dependent). The test pins the invariant that callers will not silently receive
        // a phantom certificate in either path.
        var bad = "-----BEGIN CERTIFICATE-----\n@@@-not-base64-@@@\n-----END CERTIFICATE-----\n";
        try
        {
            var coll = TrustAnchorLoader.FromPem(bad);
            Assert.Empty(coll);
        }
        catch (CryptographicException)
        {
            // Either outcome is acceptable; both prevent silent injection of an unverified anchor.
        }
    }

    [Fact]
    public void FromPemFile_reads_file_and_loads_certificates()
    {
        using var cert = CreateCert("CN=trust-file");
        var tmp = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tmp, ExportPem(cert));
            var coll = TrustAnchorLoader.FromPemFile(tmp);
            Assert.Single(coll);
            Assert.Equal(cert.Subject, coll[0].Subject);
        }
        finally
        {
            File.Delete(tmp);
        }
    }

    [Fact]
    public void FromPemFile_throws_on_missing_file()
    {
        var nonExistent = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".pem");
        Assert.False(File.Exists(nonExistent));
        Assert.Throws<FileNotFoundException>(() => TrustAnchorLoader.FromPemFile(nonExistent));
    }

    [Fact]
    public void FromPemFile_rejects_null_or_empty_path()
    {
        Assert.Throws<ArgumentNullException>(() => TrustAnchorLoader.FromPemFile(null!));
        Assert.Throws<ArgumentException>(() => TrustAnchorLoader.FromPemFile(string.Empty));
    }

    [Fact]
    public void FromPfx_imports_certificate_from_pkcs12_store()
    {
        // Cert-only PFX (no key material) avoids the macOS Apple-CC limitation where CreateSelfSigned-rooted
        // keys cannot be re-exported via Export(Pfx, password). Anchors don't need private keys anyway.
        using var cert = CreateCertWithoutKey("CN=pfx-anchor");
        var coll = new X509Certificate2Collection { cert };
        var pfx = coll.Export(X509ContentType.Pfx, "secret")!;
        var tmp = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tmp, pfx);
            var loaded = TrustAnchorLoader.FromPfx(tmp, "secret");
            Assert.Single(loaded);
            Assert.Equal(cert.Subject, loaded[0].Subject);
        }
        finally
        {
            File.Delete(tmp);
        }
    }

    [Fact]
    public void FromPfx_throws_on_wrong_password()
    {
        using var cert = CreateCertWithoutKey("CN=pfx-wrong-pwd");
        var coll = new X509Certificate2Collection { cert };
        var pfx = coll.Export(X509ContentType.Pfx, "secret")!;
        var tmp = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tmp, pfx);
            Assert.ThrowsAny<CryptographicException>(() => TrustAnchorLoader.FromPfx(tmp, "wrong"));
        }
        finally
        {
            File.Delete(tmp);
        }
    }

    [Fact]
    public void FromPfx_rejects_null_or_empty_path()
    {
        Assert.Throws<ArgumentNullException>(() => TrustAnchorLoader.FromPfx(null!, "pwd"));
        Assert.Throws<ArgumentException>(() => TrustAnchorLoader.FromPfx(string.Empty, "pwd"));
    }

    [Fact]
    public void FromPfx_default_flags_are_cross_platform_portable()
    {
        // Regression: previously the default was X509KeyStorageFlags.EphemeralKeySet which throws
        // PlatformNotSupportedException on macOS (Apple-CC requires keys to round-trip through the keychain).
        // Trust anchors don't need private keys, so the default must work on every supported platform.
        using var cert = CreateCertWithoutKey("CN=pfx-default-flags");
        var coll = new X509Certificate2Collection { cert };
        var pfx = coll.Export(X509ContentType.Pfx, "pwd")!;
        var tmp = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tmp, pfx);
            var loaded = TrustAnchorLoader.FromPfx(tmp, "pwd");
            Assert.Single(loaded);
        }
        finally
        {
            File.Delete(tmp);
        }
    }

    private static X509Certificate2 CreateCert(string subject)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var withKey = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return new X509Certificate2(withKey.Export(X509ContentType.Cert));
    }

    private static X509Certificate2 CreateCertWithoutKey(string subject) => CreateCert(subject);

    private static string ExportPem(X509Certificate2 cert)
    {
        var bytes = cert.Export(X509ContentType.Cert);
        var b64 = Convert.ToBase64String(bytes, Base64FormattingOptions.InsertLineBreaks);
        return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
    }
}
