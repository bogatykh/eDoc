using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using eDocLib;
using eDocLib.Configuration;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

public class EdocApiSurfaceTests
{
    [Fact]
    public void EdocBuilder_round_trip_data_objects()
    {
        using var pkg = Edoc.CreateNew();
        Assert.Equal(Edoc.DefaultFormatVersion, pkg.FormatVersion);

        pkg.AddDataObject(new MemoryStream(Encoding.UTF8.GetBytes("a")), "a.txt", "text/plain");
        pkg.AddDataObject(new MemoryStream(Encoding.UTF8.GetBytes("b")), "b.txt", "text/plain");
        Assert.Equal(2, pkg.DataObjectCount);
        Assert.Equal("a.txt", pkg.GetDataObject(0).Name);

        using var zip = new MemoryStream();
        pkg.Save(zip);
        zip.Position = 0;

        using var read = Edoc.Open(EdocLibConfig.Default, zip);
        Assert.Equal(2, read.DataObjectCount);
        using var r = new StreamReader(read.GetDataObject(1).Stream, Encoding.UTF8, leaveOpen: true);
        Assert.Equal("b", r.ReadToEnd());
    }

    [Fact]
    public void RemoveDataObject_and_signature()
    {
        using var pkg = Edoc.CreateNew();
        pkg.AddDataObject(new MemoryStream(Encoding.UTF8.GetBytes("x")), "x.txt", "text/plain");
        pkg.RemoveDataObjectAt(0);
        Assert.Equal(0, pkg.DataObjectCount);

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=api-remove", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        pkg.AddDataObject(new MemoryStream(Encoding.UTF8.GetBytes("p")), "doc.txt", "text/plain");
        var job = new EdocBasicSigningJob(pkg, cert, DateTimeOffset.Parse("2025-01-15T10:00:00Z"));
        var prep = job.Prepare();
        var sigBytes = cert.GetRSAPrivateKey()!.SignData(prep.GetSignableBytes(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        job.Complete(prep, sigBytes);
        Assert.Equal(1, pkg.SignatureCount);

        var info = pkg.GetSignature(0);
        Assert.Equal(EdocMaterialProfile.Basic, info.MaterialProfile);
        Assert.NotEmpty(info.SignatureValueOctets);

        pkg.RemoveSignatureAt(0);
        Assert.Equal(0, pkg.SignatureCount);
    }

    [Fact]
    public void Edoc_save_rewinds_payload_streams_after_two_phase_prepare_sign()
    {
        var payload = "stream-rewind"u8.ToArray();
        using var pkg = Edoc.CreateNew();
        pkg.AddDataObject(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=rewind", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var job = new EdocBasicSigningJob(pkg, cert, DateTimeOffset.Parse("2025-02-01T10:00:00Z"));
        var prep = job.Prepare();
        var sigBytes = cert.GetRSAPrivateKey()!.SignData(
            prep.GetSignableBytes(),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        job.Complete(prep, sigBytes);

        using var zip = new MemoryStream();
        pkg.Save(zip);
        zip.Position = 0;
        using var archive = new ZipArchive(zip, ZipArchiveMode.Read, leaveOpen: true);
        var entry = archive.GetEntry("doc.txt") ?? throw new InvalidOperationException("doc.txt missing from ZIP.");
        using var er = entry.Open();
        using var r = new MemoryStream();
        er.CopyTo(r);
        Assert.Equal(payload, r.ToArray());
    }

    [Fact]
    public void EdocBasicSigningJob_RsaDigestPreference_flows_to_PrepareSign()
    {
        using var pkg = Edoc.CreateNew();
        pkg.AddDataObject(new MemoryStream(Encoding.UTF8.GetBytes("p")), "doc.txt", "text/plain");
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=api-rsa384", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var job = new EdocBasicSigningJob(pkg, cert, DateTimeOffset.Parse("2025-01-15T10:00:00Z"))
        {
            RsaDigestPreference = XadesRsaDigestPreference.Sha384,
        };
        var prep = job.Prepare();
        Assert.Equal(XadesSignatureAlgorithms.RsaWithSha384, prep.SignatureMethodUri);
    }

    [Fact]
    public void Open_corrupt_zip_wraps_EdocException()
    {
        var buf = Encoding.UTF8.GetBytes("not a zip");
        using var ms = new MemoryStream(buf);
        var ex = Assert.Throws<EdocException>(() => Edoc.Open(EdocLibConfig.Default, ms));
        Assert.NotEqual(EdocFailureKind.Unknown, ex.Kind);
    }

    [Fact]
    public void IsLikelyEdocContainer_detects_saved_package()
    {
        using var pkg = Edoc.CreateNew();
        pkg.AddDataObject(new MemoryStream(Encoding.UTF8.GetBytes("z")), "z.txt", "text/plain");
        using var zip = new MemoryStream();
        pkg.Save(zip);
        zip.Position = 0;
        Assert.True(Edoc.TryDetectContainer(zip, out var probe), probe.RejectionReason);
        Assert.True(probe.IsLikelyAsicE);
    }

    [Fact]
    public void EdocReadValidationResult_exposes_aggregate_validation_interface()
    {
        using var pkg = Edoc.CreateNew();
        pkg.AddDataObject(new MemoryStream(Encoding.UTF8.GetBytes("z")), "z.txt", "text/plain");
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=iface", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var job = new EdocBasicSigningJob(pkg, cert, DateTimeOffset.Parse("2025-03-01T12:00:00Z"));
        var prep = job.Prepare();
        var sigBytes = cert.GetRSAPrivateKey()!.SignData(prep.GetSignableBytes(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        job.Complete(prep, sigBytes);

        var read = EdocValidation.ValidateSignatures(pkg, SignatureTrustPolicy.CryptographyOnly);
        IEdocContainerValidationResult agg = read;
        Assert.False(agg.HasWarnings);
        Assert.True(agg.AllSignaturesValid);
        Assert.Equal(pkg, agg.Edoc);
    }

    [Fact]
    public void EdocLibConfigBuilder_Create_Open_matches_Default_Open()
    {
        using var pkg = Edoc.CreateNew();
        pkg.AddDataObject(new MemoryStream(Encoding.UTF8.GetBytes("q")), "q.txt", "text/plain");
        using var zip = new MemoryStream();
        pkg.Save(zip);

        zip.Position = 0;
        using var left = Edoc.Open(EdocLibConfig.Default, zip);

        zip.Position = 0;
        using var right = Edoc.Open(EdocLibConfigBuilder.Create().Build(), zip);

        Assert.Equal(left.DataObjectCount, right.DataObjectCount);
    }

    [Fact]
    public void Default_config_is_stable_singleton()
    {
        Assert.Same(EdocLibConfig.Default, EdocLibConfig.Default);
    }

    [Fact]
    public void EdocLibInfo_reads_assembly_metadata()
    {
        Assert.False(string.IsNullOrWhiteSpace(EdocLibInfo.InformationalVersion));
        Assert.False(string.IsNullOrWhiteSpace(EdocLibInfo.AssemblyVersion));
        Assert.Equal("eDocLib", EdocLibInfo.AssemblyName);
        Assert.StartsWith("1.0.0", EdocLibInfo.AssemblyVersion, StringComparison.Ordinal);
    }

    [Fact]
    public void EdocReadValidationResult_HasWarnings_when_signature_indeterminate()
    {
        var xml = new XmlDocument();
        xml.LoadXml(
            "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"s1\"><SignedInfo>" +
            "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/></SignedInfo></Signature>");
        var sig = new RawXmlSignature(xml);
        using var edoc = Edoc.CreateNew();
        var read = new EdocReadValidationResult
        {
            Edoc = edoc,
            Signatures =
            [
                new EdocSignatureVerification
                {
                    Ordinal = 0,
                    Signature = sig,
                    Result = new SignatureValidationResult
                    {
                        Success = false,
                        ReferencesAndSignatureValid = true,
                    },
                },
            ],
        };

        Assert.True(read.HasWarnings);
        Assert.False(read.AllSignaturesValid);
    }
}
