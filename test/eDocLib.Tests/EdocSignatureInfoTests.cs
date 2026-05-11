using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// Coverage for <see cref="EdocSignatureInfo"/> read-only view: facade parity, material profile classification,
/// and the <see cref="EdocSignatureInfo.From"/> rejection of non-XAdES signatures.
/// </summary>
public class EdocSignatureInfoTests
{
    [Fact]
    public void From_rejects_null_signature()
    {
        Assert.Throws<ArgumentNullException>(() => EdocSignatureInfo.From(null!));
    }

    [Fact]
    public void From_rejects_non_xades_signature_with_argument_exception()
    {
        // The view is XAdES-specific; foreign ISignature implementations must be flagged eagerly
        // rather than crashing later when XAdES-only members are dereferenced.
        var foreign = new ForeignSignature();
        var ex = Assert.Throws<ArgumentException>(() => EdocSignatureInfo.From(foreign));
        Assert.Equal("signature", ex.ParamName);
    }

    [Fact]
    public void From_wraps_xades_signature_and_exposes_metadata()
    {
        var sig = BuildBesSignatureWithRoles(new[] { "Author" }, new SignatureProductionPlace("Riga", "Latgale", "LV-1050", "LV"));
        var info = EdocSignatureInfo.From(sig);

        Assert.NotNull(info.SigningCertificate);
        Assert.Equal(sig.Id, info.Id);
        Assert.Equal(sig.SignatureMethod, info.SignatureMethod);
        Assert.Equal(new[] { "Author" }, info.SignerRoles);
        Assert.Equal("Riga", info.SignatureProductionPlace?.City);
        Assert.NotNull(info.ClaimedSigningTime);
        Assert.NotEmpty(info.SignatureValueOctets);
    }

    [Fact]
    public void MaterialProfile_is_Basic_for_plain_bes_signature()
    {
        var sig = BuildBesSignatureWithRoles(roles: null, place: null);
        var info = EdocSignatureInfo.From(sig);
        Assert.Equal(EdocMaterialProfile.Basic, info.MaterialProfile);
    }

    [Fact]
    public async Task MaterialProfile_is_Basic_for_xades_T_without_lt_material()
    {
        // XAdES-T adds a SignatureTimeStamp but no CertificateValues / RevocationValues. Coarse profile
        // is still "Basic" because the classifier explicitly tracks LT material (XAdES-XL) presence.
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=mat-T", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var dfs = new[] { new DataFile(new MemoryStream("t"u8.ToArray()), "doc.txt", "text/plain") };
        var sig = await XadesBesSigner.SignWithTimestampAsync(
            dfs, cert, DateTimeOffset.UtcNow, new LocalSha256Rfc3161TimestampProvider());

        Assert.Equal(EdocMaterialProfile.Basic, EdocSignatureInfo.From(sig).MaterialProfile);
    }

    [Fact]
    public void MaterialProfile_is_LongTermMaterial_when_unsigned_certificate_values_present()
    {
        var sig = BuildBesSignatureWithRoles(roles: null, place: null);
        InjectUnsignedEncapsulatedX509Certificate(sig.GetSignatureOwnerDocument(), new byte[] { 0x30, 0x82, 0x01, 0x00 });

        Assert.Equal(EdocMaterialProfile.LongTermMaterial, EdocSignatureInfo.From(sig).MaterialProfile);
    }

    [Fact]
    public void MaterialProfile_is_LongTermMaterial_when_revocation_values_present()
    {
        var sig = BuildBesSignatureWithRoles(roles: null, place: null);
        InjectUnsignedOcspValue(sig.GetSignatureOwnerDocument(), new byte[] { 0x30, 0x82, 0x00, 0x10 });

        Assert.Equal(EdocMaterialProfile.LongTermMaterial, EdocSignatureInfo.From(sig).MaterialProfile);
    }

    [Fact]
    public void MaterialProfile_is_Unknown_when_archive_timestamp_present_without_lt_material()
    {
        // The classifier treats an isolated ArchiveTimeStamp without LT material as an inconsistent state
        // (XAdES-A profile mandates LT material). The current behaviour is to flag this as Unknown.
        var sig = BuildBesSignatureWithRoles(roles: null, place: null);
        InjectArchiveTimestampPlaceholder(sig.GetSignatureOwnerDocument());

        Assert.Equal(EdocMaterialProfile.Unknown, EdocSignatureInfo.From(sig).MaterialProfile);
    }

    [Fact]
    public async Task EncapsulatedTimeStampDer_returns_token_bytes_when_present()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=ts-enc", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var dfs = new[] { new DataFile(new MemoryStream("e"u8.ToArray()), "doc.txt", "text/plain") };
        var sig = await XadesBesSigner.SignWithTimestampAsync(
            dfs, cert, DateTimeOffset.UtcNow, new LocalSha256Rfc3161TimestampProvider());

        var info = EdocSignatureInfo.From(sig);
        Assert.Single(info.EncapsulatedTimeStampDer);
        Assert.NotEmpty(info.EncapsulatedTimeStampDer[0]);
    }

    [Fact]
    public void EncapsulatedTimeStampDer_is_empty_for_plain_bes()
    {
        var sig = BuildBesSignatureWithRoles(roles: null, place: null);
        Assert.Empty(EdocSignatureInfo.From(sig).EncapsulatedTimeStampDer);
    }

    [Fact]
    public void UnsignedCertificateValuesDer_lists_injected_certificates_in_document_order()
    {
        var sig = BuildBesSignatureWithRoles(roles: null, place: null);
        InjectUnsignedEncapsulatedX509Certificate(sig.GetSignatureOwnerDocument(), new byte[] { 1, 2, 3 });
        InjectUnsignedEncapsulatedX509Certificate(sig.GetSignatureOwnerDocument(), new byte[] { 4, 5, 6 });

        var info = EdocSignatureInfo.From(sig);
        Assert.Equal(2, info.UnsignedCertificateValuesDer.Count);
        Assert.Equal(new byte[] { 1, 2, 3 }, info.UnsignedCertificateValuesDer[0]);
        Assert.Equal(new byte[] { 4, 5, 6 }, info.UnsignedCertificateValuesDer[1]);
    }

    private sealed class ForeignSignature : ISignature
    {
        public string Id => "foreign";
        public string SignatureMethod => "n/a";
        public X509Certificate? SigningCertificate => null;
        public System.Collections.Generic.IReadOnlyCollection<string> SignerRoles => Array.Empty<string>();
        public SignatureProductionPlace? SignatureProductionPlace => null;
        public void WriteTo(Stream stream) => throw new NotSupportedException();
    }

    private static XadesSignature BuildBesSignatureWithRoles(string[]? roles, SignatureProductionPlace? place)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=info-bes", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var dfs = new[] { new DataFile(new MemoryStream("doc"u8.ToArray()), "doc.txt", "text/plain") };
        return XadesBesSigner.Sign(dfs, cert, DateTimeOffset.UtcNow, signerRoles: roles, productionPlace: place);
    }

    private static void InjectUnsignedEncapsulatedX509Certificate(XmlDocument doc, byte[] der)
    {
        var container = EnsureChild(EnsureChild(EnsureChild(FindQualifying(doc), "UnsignedProperties"), "UnsignedSignatureProperties"), "CertificateValues");
        var enc = doc.CreateElement(XadesSignature.XadesPrefix, "EncapsulatedX509Certificate", XadesSignature.XadesNamespaceUrl);
        enc.InnerText = Convert.ToBase64String(der);
        container.AppendChild(enc);
    }

    private static void InjectUnsignedOcspValue(XmlDocument doc, byte[] der)
    {
        var revoc = EnsureChild(EnsureChild(EnsureChild(FindQualifying(doc), "UnsignedProperties"), "UnsignedSignatureProperties"), "RevocationValues");
        var ocspValues = EnsureChild(revoc, "OCSPValues");
        var enc = doc.CreateElement(XadesSignature.XadesPrefix, "EncapsulatedOCSPValue", XadesSignature.XadesNamespaceUrl);
        enc.InnerText = Convert.ToBase64String(der);
        ocspValues.AppendChild(enc);
    }

    private static void InjectArchiveTimestampPlaceholder(XmlDocument doc)
    {
        var unsignedSigProps = EnsureChild(EnsureChild(FindQualifying(doc), "UnsignedProperties"), "UnsignedSignatureProperties");
        var archive = doc.CreateElement(XadesSignature.XadesPrefix, "ArchiveTimeStamp", XadesSignature.XadesNamespaceUrl);
        unsignedSigProps.AppendChild(archive);
    }

    private static XmlElement FindQualifying(XmlDocument doc)
    {
        var qp = doc.GetElementsByTagName("QualifyingProperties", XadesSignature.XadesNamespaceUrl);
        Assert.True(qp.Count > 0, "QualifyingProperties element not found in signature document");
        return (XmlElement)qp[0]!;
    }

    private static XmlElement EnsureChild(XmlElement parent, string localName)
    {
        foreach (XmlNode child in parent.ChildNodes)
        {
            if (child is XmlElement el && el.LocalName == localName && el.NamespaceURI == XadesSignature.XadesNamespaceUrl)
            {
                return el;
            }
        }

        var created = parent.OwnerDocument!.CreateElement(XadesSignature.XadesPrefix, localName, XadesSignature.XadesNamespaceUrl);
        parent.AppendChild(created);
        return created;
    }
}
