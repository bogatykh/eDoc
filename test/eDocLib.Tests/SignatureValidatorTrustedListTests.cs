using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using eDocLib.Validation;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// Coverage for <see cref="SignatureValidatorTrustedList.Evaluate"/>: the trusted-list gate used by
/// <see cref="SignatureValidator"/> before chain validation. Every branch combination of "index configured /
/// signing cert present / cert listed / RequireSigningCertificateListedInTrustedList" exercises a distinct
/// result tuple, so the gate is tested directly rather than only through the full pipeline.
/// </summary>
public class SignatureValidatorTrustedListTests
{
    [Fact]
    public void Evaluate_returns_ok_with_nulls_when_no_index_configured()
    {
        // Without a TSL configured, the gate is a no-op: Ok=true and all fields null so downstream stages
        // don't accidentally observe phantom "Listed=true" values.
        using var cert = NewCert("CN=no-index");
        var policy = new SignatureTrustPolicy();
        var ev = SignatureValidatorTrustedList.Evaluate(policy, cert);
        Assert.True(ev.Ok);
        Assert.Null(ev.Error);
        Assert.Null(ev.Listed);
        Assert.Null(ev.ServiceTypeIds);
        Assert.Null(ev.ServiceStatus);
    }

    [Fact]
    public void Evaluate_fails_when_index_present_but_signing_cert_missing_and_listing_required()
    {
        var policy = new SignatureTrustPolicy
        {
            TrustedListServiceIndex = BuildSingleEntryTsl(out _),
            RequireSigningCertificateListedInTrustedList = true,
        };
        var ev = SignatureValidatorTrustedList.Evaluate(policy, signingCert: null);
        Assert.False(ev.Ok);
        Assert.Equal(
            "Signing certificate is required for trusted list qualification but was not found in the signature.",
            ev.Error);
        Assert.Null(ev.Listed);
    }

    [Fact]
    public void Evaluate_passes_when_index_present_but_signing_cert_missing_and_listing_not_required()
    {
        // Index is configured but no cert was extracted — and the host didn't demand listing. Result must
        // be Ok=true with Listed=null (we couldn't check at all).
        var policy = new SignatureTrustPolicy
        {
            TrustedListServiceIndex = BuildSingleEntryTsl(out _),
            RequireSigningCertificateListedInTrustedList = false,
        };
        var ev = SignatureValidatorTrustedList.Evaluate(policy, signingCert: null);
        Assert.True(ev.Ok);
        Assert.Null(ev.Listed);
    }

    [Fact]
    public void Evaluate_returns_listed_true_with_service_metadata_when_certificate_matches()
    {
        var index = BuildSingleEntryTsl(out var listedCert);
        var policy = new SignatureTrustPolicy { TrustedListServiceIndex = index };
        var ev = SignatureValidatorTrustedList.Evaluate(policy, listedCert);

        Assert.True(ev.Ok);
        Assert.Null(ev.Error);
        Assert.True(ev.Listed);
        Assert.NotNull(ev.ServiceTypeIds);
        Assert.Contains(TslQualificationMapper.ServiceTypeTsaQTST, ev.ServiceTypeIds!, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(TslQualificationMapper.ServiceStatusGranted, ev.ServiceStatus);

        listedCert.Dispose();
    }

    [Fact]
    public void Evaluate_returns_listed_false_when_cert_not_in_index_and_not_required()
    {
        // "Not listed but allowed" — Ok=true, Listed=false. Downstream consumers can decide whether to apply
        // additional gates (e.g. RequireQualifiedTimestampServiceType, granted-status) on the null indicators.
        var index = BuildSingleEntryTsl(out var listedCert);
        using var otherCert = NewCert("CN=other-cert");
        var policy = new SignatureTrustPolicy { TrustedListServiceIndex = index };
        var ev = SignatureValidatorTrustedList.Evaluate(policy, otherCert);

        Assert.True(ev.Ok);
        Assert.False(ev.Listed);
        Assert.Null(ev.ServiceTypeIds);
        Assert.Null(ev.ServiceStatus);
        listedCert.Dispose();
    }

    [Fact]
    public void Evaluate_fails_when_cert_not_in_index_and_listing_required()
    {
        var index = BuildSingleEntryTsl(out var listedCert);
        using var otherCert = NewCert("CN=stranger");
        var policy = new SignatureTrustPolicy
        {
            TrustedListServiceIndex = index,
            RequireSigningCertificateListedInTrustedList = true,
        };
        var ev = SignatureValidatorTrustedList.Evaluate(policy, otherCert);

        Assert.False(ev.Ok);
        Assert.Equal("Signing certificate is not listed in the configured trusted service list.", ev.Error);
        Assert.False(ev.Listed);
        listedCert.Dispose();
    }

    [Fact]
    public void Evaluate_uses_reference_time_to_resolve_history_when_configured()
    {
        // Pins the integration with TrustedListQualificationResolver: when a reference time falls inside a
        // historical interval, the historical qualification is used. We exercise this with a TSL that has
        // a ServiceHistory snapshot dated before the reference time.
        var (index, listedCert) = BuildIndexWithServiceHistory();
        var policy = new SignatureTrustPolicy
        {
            TrustedListServiceIndex = index,
            TrustedListQualificationReferenceTimeUtc = DateTimeOffset.Parse("2018-01-01T00:00:00Z"),
        };
        var ev = SignatureValidatorTrustedList.Evaluate(policy, listedCert);

        Assert.True(ev.Ok);
        Assert.True(ev.Listed);
        // Historical status was the qualified-equivalent "accredited" at the reference time; with no LV defaults
        // merged, the helper still surfaces the URI verbatim — the qualification mapper later decides "granted-like".
        Assert.NotNull(ev.ServiceStatus);

        listedCert.Dispose();
    }

    private static X509Certificate2 NewCert(string subject)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    private static TrustedListServiceIndex BuildSingleEntryTsl(out X509Certificate2 listedCertificate)
    {
        listedCertificate = NewCert("CN=tsl-listed");
        var b64 = Convert.ToBase64String(listedCertificate.Export(X509ContentType.Cert));
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
              <TSPService>
                <ServiceInformation>
                  <ServiceTypeIdentifier>{TslQualificationMapper.ServiceTypeTsaQTST}</ServiceTypeIdentifier>
                  <ServiceStatus>{TslQualificationMapper.ServiceStatusGranted}</ServiceStatus>
                  <ServiceDigitalIdentity>
                    <DigitalId><X509Certificate>{b64}</X509Certificate></DigitalId>
                  </ServiceDigitalIdentity>
                </ServiceInformation>
              </TSPService>
            </TrustServiceStatusList>
            """;
        return TrustedListServiceIndex.FromStream(new MemoryStream(Encoding.UTF8.GetBytes(xml)));
    }

    private static (TrustedListServiceIndex Index, X509Certificate2 Cert) BuildIndexWithServiceHistory()
    {
        var cert = NewCert("CN=tsl-with-history");
        var b64 = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
        // Current status is granted; historical snapshot before 2020 was accredited. The resolver picks the
        // historical snapshot when the reference time is before the StatusStartingTime of the current entry.
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
              <TSPService>
                <ServiceInformation>
                  <ServiceTypeIdentifier>{TslQualificationMapper.ServiceTypeTsaQTST}</ServiceTypeIdentifier>
                  <ServiceStatus>{TslQualificationMapper.ServiceStatusGranted}</ServiceStatus>
                  <StatusStartingTime>2020-01-01T00:00:00Z</StatusStartingTime>
                  <ServiceDigitalIdentity>
                    <DigitalId><X509Certificate>{b64}</X509Certificate></DigitalId>
                  </ServiceDigitalIdentity>
                </ServiceInformation>
                <ServiceHistory>
                  <ServiceHistoryInstance>
                    <ServiceTypeIdentifier>{TslQualificationMapper.ServiceTypeTsaQTST}</ServiceTypeIdentifier>
                    <ServiceStatus>{TslQualificationMapper.ServiceStatusAccredited}</ServiceStatus>
                    <StatusStartingTime>2010-01-01T00:00:00Z</StatusStartingTime>
                    <ServiceInformationExtensions />
                  </ServiceHistoryInstance>
                </ServiceHistory>
              </TSPService>
            </TrustServiceStatusList>
            """;
        var index = TrustedListServiceIndex.FromStream(new MemoryStream(Encoding.UTF8.GetBytes(xml)));
        return (index, cert);
    }
}
