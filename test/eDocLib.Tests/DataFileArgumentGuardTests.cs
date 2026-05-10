using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary>Guard clauses reaching signing via <see cref="XadesBesSigner"/> / payload enumeration.</summary>
public class DataFileArgumentGuardTests
{
    [Fact]
    public void Sign_rejects_empty_relative_name_on_data_file()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=empty-name", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var dfs = new[] { new DataFile(new MemoryStream("a"u8.ToArray()), string.Empty, "text/plain") };

        Assert.Throws<ArgumentException>(() =>
            XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-12-15T11:00:00Z")));
    }

    [Fact]
    public void DataFile_constructor_rejects_null_stream()
    {
        Assert.Throws<ArgumentNullException>(() => new DataFile(null!, "n.txt", "text/plain"));
    }

    [Fact]
    public void DataFile_constructor_with_mime_rejects_null_mime()
    {
        Assert.Throws<ArgumentNullException>(() => new DataFile(new MemoryStream(), "n.txt", null!));
    }
}
