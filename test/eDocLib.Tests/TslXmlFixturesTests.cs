using System.Security.Cryptography.X509Certificates;
using eDocLib.Validation;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// Regression tests over minimal ETSI TS 119 612 v2 XML under <c>Fixtures/tsl</c> (V-05 / EP-41).
/// </summary>
public class TslXmlFixturesTests
{
    private static string FixturePath(string fileName) =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "tsl", fileName);

    private static X509Certificate2 LoadListingCertificate() =>
        new(FixturePath("listing-cert.cer"));

    [Theory]
    [InlineData("minimal-qes-granted.xml", true, false, true)]
    [InlineData("minimal-qes-national.xml", true, false, true)]
    [InlineData("minimal-qeseal-granted.xml", false, true, true)]
    public void TrustedListServiceIndex_fixture_maps_via_TslQualificationMapper(
        string xmlFile,
        bool expectSign,
        bool expectSeal,
        bool expectGrantedLike)
    {
        using var cert = LoadListingCertificate();
        using var stream = File.OpenRead(FixturePath(xmlFile));
        var index = TrustedListServiceIndex.FromStream(stream);
        Assert.True(index.TryGetQualification(cert, out var q), $"Certificate should be listed in {xmlFile}");
        var m = TslQualificationMapper.Map(q!.ServiceTypeIdentifiers, q.ServiceStatusUri);
        Assert.Equal(expectSign, m.SuggestsQualifiedElectronicSignature);
        Assert.Equal(expectSeal, m.SuggestsQualifiedElectronicSeal);
        Assert.Equal(expectGrantedLike, m.ServiceStatusIsGranted);
    }

    [Fact]
    public void TrustedListReader_TryLoad_exposes_scheme_information_metadata()
    {
        using var stream = File.OpenRead(FixturePath("minimal-tsl-scheme-information.xml"));
        Assert.True(
            TrustedListReader.TryLoad(stream, verifyXmlSignature: false, out var index, out var meta, out var err),
            err);
        Assert.NotNull(index);
        Assert.NotNull(meta);
        Assert.Equal(42L, meta!.TslSequenceNumber);
        Assert.Equal("LV", meta.SchemeTerritory);
        Assert.NotNull(meta.ListIssueDateTime);
        Assert.Equal(2025, meta.ListIssueDateTime!.Value.Year);
        Assert.NotNull(meta.NextUpdate);
        Assert.Equal(7, meta.NextUpdate!.Value.Month);
    }

    [Fact]
    public void TrustedListDocumentMetadata_FromXDocument_handles_flat_NextUpdate_text()
    {
        var xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
              <SchemeInformation>
                <NextUpdate>2030-12-31T23:59:59Z</NextUpdate>
              </SchemeInformation>
            </TrustServiceStatusList>
            """;
        var doc = System.Xml.Linq.XDocument.Parse(xml, System.Xml.Linq.LoadOptions.PreserveWhitespace);
        var meta = TrustedListDocumentMetadata.FromXDocument(doc);
        Assert.NotNull(meta.NextUpdate);
        Assert.Equal(2030, meta.NextUpdate!.Value.Year);
    }

    [Fact]
    public void TrustedListServiceIndex_ServiceHistory_parsed_when_present()
    {
        using var cert = LoadListingCertificate();
        using var stream = File.OpenRead(FixturePath("minimal-qes-with-service-history.xml"));
        var index = TrustedListServiceIndex.FromStream(stream);
        Assert.True(index.TryGetQualification(cert, out var q), "Fixture cert should be listed");
        Assert.NotNull(q!.ServiceHistory);
        Assert.Single(q.ServiceHistory);
        var h = q.ServiceHistory[0];
        Assert.Equal("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn", h.ServiceStatusUri);
        Assert.NotNull(h.StatusStartingTime);
        Assert.Equal(2019, h.StatusStartingTime!.Value.Year);
        Assert.Equal(6, h.StatusStartingTime.Value.Month);
        Assert.Contains(
            TslQualificationMapper.ServiceTypeQCertESign,
            h.ServiceTypeIdentifiers,
            StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void TrustedListServiceIndex_fixture_nested_ServiceTypeIdentifier_URI_extracts_type()
    {
        using var cert = LoadListingCertificate();
        using var stream = File.OpenRead(FixturePath("minimal-qes-nested-uri.xml"));
        var index = TrustedListServiceIndex.FromStream(stream);
        Assert.True(index.TryGetQualification(cert, out var q));
        Assert.Contains(TslQualificationMapper.ServiceTypeQCertESign, q!.ServiceTypeIdentifiers, StringComparer.OrdinalIgnoreCase);
        var m = TslQualificationMapper.Map(q.ServiceTypeIdentifiers, q.ServiceStatusUri);
        Assert.True(m.SuggestsQualifiedElectronicSignature);
        Assert.True(m.ServiceStatusIsGranted);
    }

    [Fact]
    public void TrustedListServiceIndex_fixture_merge_two_services_yields_both_qualification_hints()
    {
        using var cert = LoadListingCertificate();
        using var stream = File.OpenRead(FixturePath("minimal-merge-two-services-same-cert.xml"));
        var index = TrustedListServiceIndex.FromStream(stream);
        Assert.True(index.TryGetQualification(cert, out var q));
        Assert.Equal(2, q!.ServiceTypeIdentifiers.Count);
        var m = TslQualificationMapper.Map(q.ServiceTypeIdentifiers, q.ServiceStatusUri);
        Assert.True(m.SuggestsQualifiedElectronicSignature);
        Assert.True(m.SuggestsQualifiedElectronicSeal);
        Assert.True(m.ServiceStatusIsGranted);
    }

    [Fact]
    public void TslQualificationMappingOptions_extra_uris_apply_to_fixture_indexed_qualification()
    {
        const string extraType = "http://national.example/trstsvc/custom-qes";
        const string extraStatus = "http://national.example/tsl/active";
        using var cert = LoadListingCertificate();
        using var stream = File.OpenRead(FixturePath("minimal-qeseal-granted.xml"));
        var index = TrustedListServiceIndex.FromStream(stream);
        Assert.True(index.TryGetQualification(cert, out var q));
        var types = q!.ServiceTypeIdentifiers.Concat(new[] { extraType }).ToList();
        var opt = new TslQualificationMappingOptions
        {
            ExtraQualifiedEsignServiceTypeUris = new[] { extraType },
            ExtraGrantedLikeServiceStatusUris = new[] { extraStatus },
        };
        var mDefault = TslQualificationMapper.Map(types, extraStatus);
        Assert.False(mDefault.SuggestsQualifiedElectronicSignature);
        Assert.False(mDefault.ServiceStatusIsGranted);
        var m = TslQualificationMapper.Map(types, extraStatus, opt);
        Assert.True(m.SuggestsQualifiedElectronicSignature);
        Assert.True(m.SuggestsQualifiedElectronicSeal);
        Assert.True(m.ServiceStatusIsGranted);
    }
}
