using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using eDocLib.Asic.Xades;
using eDocLib.Timestamp;
using eDocLib.Validation;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// Coverage for <see cref="XadesUnsignedEmbeddedValues"/> reader semantics, in particular the contract that
/// <see cref="XadesUnsignedEmbeddedValues.HasEncapsulatedSignatureTimeStamp"/> reflects element presence,
/// not Base64 validity. Treating malformed Base64 as "no timestamp" would let an attacker who tampers with
/// the unsigned timestamp property silently bypass <see cref="SignatureTimestampImprintPolicy.RequireWhenPresent"/>.
/// </summary>
public class XadesUnsignedEmbeddedValuesTests
{
    [Fact]
    public async Task HasEncapsulatedSignatureTimeStamp_true_for_valid_token()
    {
        using var signer = await BuildTimestampedSignatureAsync();
        var doc = signer.Signature.GetSignatureOwnerDocument();
        Assert.True(XadesUnsignedEmbeddedValues.HasEncapsulatedSignatureTimeStamp(doc));
    }

    [Fact]
    public async Task HasEncapsulatedSignatureTimeStamp_false_when_no_timestamp_at_all()
    {
        var sig = BuildPlainBesSignature();
        var doc = sig.GetSignatureOwnerDocument();
        Assert.False(XadesUnsignedEmbeddedValues.HasEncapsulatedSignatureTimeStamp(doc));
    }

    [Fact]
    public async Task HasEncapsulatedSignatureTimeStamp_true_when_element_present_but_base64_corrupted()
    {
        // Regression: previously the helper returned false when InnerText was non-Base64, treating the
        // element as absent. A document trip through SignatureTrustPolicy.CryptographyAndTimestampImprint
        // would then bypass imprint verification — exploitable because unsigned properties are not
        // cryptographically protected. After the fix, presence is element-based and validation must fail.
        using var signer = await BuildTimestampedSignatureAsync();
        var doc = signer.Signature.GetSignatureOwnerDocument();
        CorruptEncapsulatedTimestampBase64(doc);

        Assert.True(XadesUnsignedEmbeddedValues.HasEncapsulatedSignatureTimeStamp(doc));
    }

    [Fact]
    public async Task ReadEncapsulatedSignatureTimeStamps_returns_decoded_der_for_valid_token()
    {
        using var signer = await BuildTimestampedSignatureAsync();
        var doc = signer.Signature.GetSignatureOwnerDocument();
        var list = XadesUnsignedEmbeddedValues.ReadEncapsulatedSignatureTimeStamps(doc);
        Assert.Single(list);
        Assert.NotEmpty(list[0]);
    }

    [Fact]
    public async Task ReadEncapsulatedSignatureTimeStamps_returns_empty_for_corrupted_base64()
    {
        // Companion to the Has* regression: the byte reader API still cannot return malformed entries; it
        // exposes only decodable DER. Callers that need the "present-but-malformed" signal should consult
        // HasEncapsulatedSignatureTimeStamp first.
        using var signer = await BuildTimestampedSignatureAsync();
        var doc = signer.Signature.GetSignatureOwnerDocument();
        CorruptEncapsulatedTimestampBase64(doc);

        var list = XadesUnsignedEmbeddedValues.ReadEncapsulatedSignatureTimeStamps(doc);
        Assert.Empty(list);
    }

    [Fact]
    public async Task EdocValidation_imprint_policy_now_fails_when_timestamp_base64_is_corrupted()
    {
        // Security regression: validator must surface the tampered timestamp under RequireWhenPresent.
        using var signer = await BuildTimestampedSignatureAsync();
        CorruptEncapsulatedTimestampBase64(signer.Signature.GetSignatureOwnerDocument());

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(signer.Payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(signer.Signature);

        using var ms = new MemoryStream();
        edoc.Save(ms);
        ms.Position = 0;

        var report = await EdocValidation.OpenAndValidateAsync(ms, SignatureTrustPolicy.CryptographyAndTimestampImprint);
        Assert.False(report.AllSignaturesValid);
        Assert.False(report.Signatures[0].Result.SignatureTimestampImprintValid);
        Assert.Contains("Base64", report.Signatures[0].Result.Error ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task HasEncapsulatedSignatureTimeStamp_does_not_match_archive_timestamp()
    {
        // XPath under //xades:SignatureTimeStamp must not match xades:ArchiveTimeStamp (XAdES-A) entries.
        var doc = BuildSyntheticSignatureDocumentWithArchiveTimestampOnly();
        Assert.False(XadesUnsignedEmbeddedValues.HasEncapsulatedSignatureTimeStamp(doc));
    }

    [Fact]
    public async Task ReadEncapsulatedSignatureTimeStamps_does_not_include_archive_timestamp()
    {
        var doc = BuildSyntheticSignatureDocumentWithArchiveTimestampOnly();
        var list = XadesUnsignedEmbeddedValues.ReadEncapsulatedSignatureTimeStamps(doc);
        Assert.Empty(list);
    }

    [Fact]
    public void ReadEncapsulatedX509Certificates_returns_empty_for_no_unsigned_certificates()
    {
        var sig = BuildPlainBesSignature();
        var list = XadesUnsignedEmbeddedValues.ReadEncapsulatedX509Certificates(sig.GetSignatureOwnerDocument());
        Assert.Empty(list);
    }

    [Fact]
    public void Reader_null_arguments_throw()
    {
        Assert.Throws<ArgumentNullException>(() => XadesUnsignedEmbeddedValues.HasEncapsulatedSignatureTimeStamp(null!));
        Assert.Throws<ArgumentNullException>(() => XadesUnsignedEmbeddedValues.ReadEncapsulatedSignatureTimeStamps(null!));
        Assert.Throws<ArgumentNullException>(() => XadesUnsignedEmbeddedValues.ReadEncapsulatedX509Certificates(null!));
        Assert.Throws<ArgumentNullException>(() => XadesUnsignedEmbeddedValues.ReadEncapsulatedPkcs7CertificateData(null!));
        Assert.Throws<ArgumentNullException>(() => XadesUnsignedEmbeddedValues.ReadEncapsulatedOcspResponses(null!));
        Assert.Throws<ArgumentNullException>(() => XadesUnsignedEmbeddedValues.ReadEncapsulatedCrls(null!));
    }

    private static void CorruptEncapsulatedTimestampBase64(XmlDocument doc)
    {
        var nsm = new XmlNamespaceManager(doc.NameTable);
        nsm.AddNamespace("xades", XadesSignature.XadesNamespaceUrl);
        var el = doc.SelectSingleNode("//xades:SignatureTimeStamp/xades:EncapsulatedTimeStamp", nsm) as XmlElement;
        Assert.NotNull(el);
        // Replace InnerText with sequence that cannot be Base64-decoded (contains characters outside the Base64 alphabet).
        el!.InnerText = "@@@-NOT-BASE64-@@@";
    }

    private static XmlDocument BuildSyntheticSignatureDocumentWithArchiveTimestampOnly()
    {
        // Direct DOM build: minimal ds:Signature shell with QualifyingProperties holding only an ArchiveTimeStamp
        // (not a SignatureTimeStamp). Avoids needing a full ASN.1 token; we just need to drive the XPath.
        var xml = $$"""
            <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="{{XadesSignature.XadesNamespaceUrl}}">
              <ds:SignedInfo />
              <ds:SignatureValue />
              <ds:Object>
                <xades:QualifyingProperties Target="#sig">
                  <xades:UnsignedProperties>
                    <xades:UnsignedSignatureProperties>
                      <xades:ArchiveTimeStamp>
                        <xades:EncapsulatedTimeStamp>AAECAw==</xades:EncapsulatedTimeStamp>
                      </xades:ArchiveTimeStamp>
                    </xades:UnsignedSignatureProperties>
                  </xades:UnsignedProperties>
                </xades:QualifyingProperties>
              </ds:Object>
            </ds:Signature>
            """;
        var doc = new XmlDocument { PreserveWhitespace = false };
        doc.LoadXml(xml);
        return doc;
    }

    private static XadesSignature BuildPlainBesSignature()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=embedded-values", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = Encoding.UTF8.GetBytes("plain-bes");
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        return XadesBesSigner.Sign(dfs, cert, DateTimeOffset.UtcNow);
    }

    private static async Task<TimestampedSignerHandle> BuildTimestampedSignatureAsync()
    {
        var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=embedded-values-ts", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = Encoding.UTF8.GetBytes("ts-payload");
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = await XadesBesSigner.SignWithTimestampAsync(
            dfs,
            cert,
            DateTimeOffset.UtcNow,
            new LocalSha256Rfc3161TimestampProvider());
        return new TimestampedSignerHandle(sig, payload, rsa, cert);
    }

    private sealed class TimestampedSignerHandle : IDisposable
    {
        public TimestampedSignerHandle(XadesSignature signature, byte[] payload, RSA rsa, X509Certificate2 cert)
        {
            Signature = signature;
            Payload = payload;
            _rsa = rsa;
            _cert = cert;
        }

        public XadesSignature Signature { get; }

        public byte[] Payload { get; }

        private readonly RSA _rsa;
        private readonly X509Certificate2 _cert;

        public void Dispose()
        {
            _cert.Dispose();
            _rsa.Dispose();
        }
    }
}
