using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Xml;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// Coverage for <see cref="XadesSignature"/> DOM parsing surface: signer roles, signature production place,
/// claimed signing time (timezone / culture-independent parsing), signing certificate lookup, signature element
/// discovery, and the round-trip serializer.
/// </summary>
public class XadesSignatureDomParsingTests
{
    [Fact]
    public void Ctor_throws_on_null_document()
    {
        Assert.Throws<ArgumentNullException>(() => new XadesSignature(null!));
    }

    [Fact]
    public void Ctor_throws_on_document_without_signature_element()
    {
        var doc = new XmlDocument();
        doc.LoadXml("<root/>");
        var ex = Assert.Throws<ArgumentException>(() => new XadesSignature(doc));
        Assert.Equal("document", ex.ParamName);
    }

    [Fact]
    public void Ctor_finds_nested_ds_Signature_element()
    {
        var doc = new XmlDocument { PreserveWhitespace = false };
        doc.LoadXml($"<wrap xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:Signature/></wrap>");
        // The constructor accepts a nested Signature, but the inner XmlDocument's SignedXml.LoadXml
        // requires a well-formed signature shape — so we verify only that FindSignatureElement returns
        // the inner node through the public surface.
        var inner = XadesSignature.FindSignatureElement(doc);
        Assert.NotNull(inner);
        Assert.Equal("Signature", inner!.LocalName);
    }

    [Fact]
    public void FindSignatureElement_returns_null_for_empty_document()
    {
        var doc = new XmlDocument();
        Assert.Null(XadesSignature.FindSignatureElement(doc));
    }

    [Fact]
    public void SignerRoles_returns_all_claimed_roles_trimmed()
    {
        var sig = SignBesWith(roles: new[] { "  Author  ", "Reviewer" }, place: null, signingTime: DateTimeOffset.UtcNow);
        Assert.Equal(new[] { "Author", "Reviewer" }, sig.SignerRoles);
    }

    [Fact]
    public void SignerRoles_is_empty_when_no_roles_supplied()
    {
        var sig = SignBesWith(roles: null, place: null, signingTime: DateTimeOffset.UtcNow);
        Assert.Empty(sig.SignerRoles);
    }

    [Fact]
    public void SignatureProductionPlace_returns_null_when_omitted()
    {
        var sig = SignBesWith(roles: null, place: null, signingTime: DateTimeOffset.UtcNow);
        Assert.Null(sig.SignatureProductionPlace);
    }

    [Fact]
    public void SignatureProductionPlace_returns_full_record_when_all_fields_supplied()
    {
        var place = new SignatureProductionPlace("Riga", "Latgale", "LV-1050", "LV");
        var sig = SignBesWith(roles: null, place: place, signingTime: DateTimeOffset.UtcNow);
        Assert.Equal(place, sig.SignatureProductionPlace);
    }

    [Fact]
    public void SignatureProductionPlace_partial_fields_are_preserved_as_null_otherwise()
    {
        var partial = new SignatureProductionPlace(City: "Riga", StateOrProvince: null, PostalCode: null, CountryName: "LV");
        var sig = SignBesWith(roles: null, place: partial, signingTime: DateTimeOffset.UtcNow);
        var parsed = sig.SignatureProductionPlace;
        Assert.NotNull(parsed);
        Assert.Equal("Riga", parsed!.City);
        Assert.Null(parsed.StateOrProvince);
        Assert.Null(parsed.PostalCode);
        Assert.Equal("LV", parsed.CountryName);
    }

    [Fact]
    public void ClaimedSigningTime_returns_signing_time_in_utc()
    {
        // Signer writes SigningTime with millisecond precision; reader should preserve the instant.
        var when = DateTimeOffset.Parse("2024-05-02T10:11:12Z", CultureInfo.InvariantCulture);
        var sig = SignBesWith(roles: null, place: null, signingTime: when);

        var parsed = sig.ClaimedSigningTime;
        Assert.NotNull(parsed);
        Assert.Equal(when.ToUniversalTime(), parsed!.Value.ToUniversalTime());
    }

    [Fact]
    public void ClaimedSigningTime_is_culture_invariant()
    {
        // Regression: previously TryParse used the current culture, which would diverge for some locales
        // (e.g. Turkish-I or non-Gregorian calendars). Forcing the locale during parsing must not affect the result.
        var original = Thread.CurrentThread.CurrentCulture;
        try
        {
            Thread.CurrentThread.CurrentCulture = new CultureInfo("tr-TR");
            var when = DateTimeOffset.Parse("2024-05-02T10:11:12Z", CultureInfo.InvariantCulture);
            var sig = SignBesWith(roles: null, place: null, signingTime: when);
            var parsed = sig.ClaimedSigningTime;
            Assert.NotNull(parsed);
            Assert.Equal(when.ToUniversalTime(), parsed!.Value.ToUniversalTime());
        }
        finally
        {
            Thread.CurrentThread.CurrentCulture = original;
        }
    }

    [Fact]
    public void ClaimedSigningTime_assumes_utc_when_offset_missing_so_validators_agree_across_machines()
    {
        // Regression: previously TryParse with default styles treated naïve datetimes as local time, so the
        // parsed instant drifted with the host's local timezone. AssumeUniversal pins the interpretation.
        var doc = SyntheticSignatureDocWithSigningTime("2024-05-02T10:11:12");
        var sig = new XadesSignature(doc);
        var parsed = sig.ClaimedSigningTime;
        Assert.NotNull(parsed);
        Assert.Equal(DateTimeOffset.Parse("2024-05-02T10:11:12Z", CultureInfo.InvariantCulture), parsed!.Value.ToUniversalTime());
    }

    [Fact]
    public void ClaimedSigningTime_returns_null_for_unparseable_value()
    {
        var doc = SyntheticSignatureDocWithSigningTime("not-a-date");
        var sig = new XadesSignature(doc);
        Assert.Null(sig.ClaimedSigningTime);
    }

    [Fact]
    public void ClaimedSigningTime_returns_null_when_absent()
    {
        // An XAdES signature without a SigningTime element (rare but possible in malformed inputs)
        // must surface as null rather than throwing.
        var doc = SyntheticSignatureDocWithSigningTime(value: null);
        var sig = new XadesSignature(doc);
        Assert.Null(sig.ClaimedSigningTime);
    }

    [Fact]
    public void SigningCertificate_is_populated_for_freshly_signed_document()
    {
        var sig = SignBesWith(roles: null, place: null, signingTime: DateTimeOffset.UtcNow);
        Assert.NotNull(sig.SigningCertificate);
    }

    [Fact]
    public void GetSignatureValueOctets_returns_non_empty_bytes()
    {
        var sig = SignBesWith(roles: null, place: null, signingTime: DateTimeOffset.UtcNow);
        var bytes = sig.GetSignatureValueOctets();
        Assert.NotEmpty(bytes);
    }

    [Fact]
    public void Id_and_SignatureMethod_return_strings_never_null()
    {
        // Both accessors are advertised as string (not string?). The contract is that they NEVER return null
        // even if the underlying SignedXml has not been populated yet (returns empty string instead).
        var sig = SignBesWith(roles: null, place: null, signingTime: DateTimeOffset.UtcNow);
        Assert.NotNull(sig.Id);
        Assert.NotNull(sig.SignatureMethod);
        Assert.NotEqual(string.Empty, sig.Id);
        Assert.NotEqual(string.Empty, sig.SignatureMethod);
    }

    [Fact]
    public void WriteTo_emits_utf8_without_bom()
    {
        var sig = SignBesWith(roles: null, place: null, signingTime: DateTimeOffset.UtcNow);
        using var ms = new MemoryStream();
        sig.WriteTo(ms);
        var bytes = ms.ToArray();
        Assert.True(bytes.Length > 3);
        // UTF-8 BOM is EF BB BF. Asserting its absence keeps interoperability with strict XML parsers.
        Assert.False(bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF, "WriteTo must not emit a UTF-8 BOM.");
    }

    [Fact]
    public void WriteTo_round_trips_through_XadesSignature_constructor()
    {
        var sig = SignBesWith(roles: new[] { "Author" }, place: null, signingTime: DateTimeOffset.UtcNow);

        using var ms = new MemoryStream();
        sig.WriteTo(ms);
        ms.Position = 0;

        var doc = new XmlDocument { PreserveWhitespace = false };
        doc.Load(ms);
        var reloaded = new XadesSignature(doc);
        Assert.Equal(sig.Id, reloaded.Id);
        Assert.Equal(sig.SignerRoles, reloaded.SignerRoles);
    }

    private static XadesSignature SignBesWith(string[]? roles, SignatureProductionPlace? place, DateTimeOffset signingTime)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=parse-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var dfs = new[] { new DataFile(new MemoryStream("p"u8.ToArray()), "doc.txt", "text/plain") };
        return XadesBesSigner.Sign(dfs, cert, signingTime, signerRoles: roles, productionPlace: place);
    }

    private static XmlDocument SyntheticSignatureDocWithSigningTime(string? value)
    {
        // Crafts the minimal DOM that XadesSignature(XmlDocument) accepts (a ds:Signature root) and a
        // QualifyingProperties subtree carrying just SigningTime — enough to drive the parser without
        // needing to fabricate a SignedInfo.
        var signingTimeFragment = value is null
            ? string.Empty
            : $"<xades:SigningTime>{value}</xades:SigningTime>";
        var xml = $$"""
            <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="{{XadesSignature.XadesNamespaceUrl}}" Id="synthetic">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
                <ds:Reference URI="#sp">
                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
                  <ds:DigestValue>AA==</ds:DigestValue>
                </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue>AA==</ds:SignatureValue>
              <ds:Object>
                <xades:QualifyingProperties Target="#synthetic">
                  <xades:SignedProperties Id="sp">
                    <xades:SignedSignatureProperties>
                      {{signingTimeFragment}}
                    </xades:SignedSignatureProperties>
                  </xades:SignedProperties>
                </xades:QualifyingProperties>
              </ds:Object>
            </ds:Signature>
            """;
        var doc = new XmlDocument { PreserveWhitespace = false };
        doc.LoadXml(xml);
        return doc;
    }
}
