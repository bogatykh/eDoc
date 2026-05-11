using System.Security.Cryptography.X509Certificates;
using eDocLib.Validation;
using eDocLib.Asic.Xades;

namespace eDocLib.Validation.Reporting;

/// <summary>Derives reporting qualification enums from <see cref="SignatureValidationResult"/> and <see cref="SignatureTrustPolicy"/>.</summary>
internal static class ValidationReportQualifications
{
    /// <summary>Gets validation signature type.</summary>
    public static ValidationSignatureType GetValidationSignatureType(XadesSignature? signature) =>
        signature is null ? ValidationSignatureType.UnknownType : ValidationSignatureType.EdocV2;

    /// <summary>Estimates signature profile.</summary>
    public static SignatureProfile EstimateSignatureProfile(XadesSignature? signature)
    {
        if (signature is null)
        {
            return SignatureProfile.UnknownSignature;
        }

        var hasLtMaterial = signature.UnsignedEncapsulatedOcspDer.Count > 0
            || signature.UnsignedEncapsulatedCrlDer.Count > 0
            || signature.UnsignedEncapsulatedX509Der.Count > 0
            || signature.UnsignedEncapsulatedPkcs7Der.Count > 0;

        if (hasLtMaterial)
        {
            return SignatureProfile.QualifiedSignature;
        }

        return SignatureProfile.BasicSignature;
    }

    /// <summary>Estimates signature qualification.</summary>
    public static SignatureQualification EstimateSignatureQualification(
        SignatureValidationResult result,
        X509Certificate2? signingCertificate = null)
    {
        if (!result.ReferencesAndSignatureValid)
        {
            return SignatureQualification.Unknown;
        }

        var q = result.TrustedListQualificationIndicators;
        if (q?.ServiceStatusIsGranted == true)
        {
            if (q.SuggestsQualifiedElectronicSignature)
            {
                return SignatureQualification.QESig;
            }

            if (q.SuggestsQualifiedElectronicSeal)
            {
                return SignatureQualification.QESeal;
            }
        }

        if (q?.SuggestsQualifiedElectronicSignature == true)
        {
            return SignatureQualification.ADESig;
        }

        if (q?.SuggestsQualifiedElectronicSeal == true)
        {
            return SignatureQualification.ADESeal;
        }

        if (signingCertificate is not null
            && SignerCertificateQualificationHeuristics.TryReadEtsiQcStatements(signingCertificate, out var qc))
        {
            if (qc.Eseal && !qc.Esign)
            {
                return SignatureQualification.ADESeal;
            }

            if (qc.Esign && !qc.Eseal)
            {
                return SignatureQualification.ADESig;
            }
        }

        if (result.Success)
        {
            return SignatureQualification.ADESig;
        }

        return SignatureQualification.Unknown;
    }

    /// <summary>Estimates signer certificate qualification.</summary>
    public static CertificateQualification EstimateSignerCertificateQualification(
        SignatureValidationResult result,
        X509Certificate2? signingCertificate = null)
    {
        var q = result.TrustedListQualificationIndicators;
        if (q is not null)
        {
            if (q.ServiceStatusIsGranted == true)
            {
                if (q.SuggestsQualifiedElectronicSignature)
                {
                    return CertificateQualification.QcESig;
                }

                if (q.SuggestsQualifiedElectronicSeal)
                {
                    return CertificateQualification.QcESeal;
                }
            }

            if (q.SuggestsQualifiedElectronicSignature)
            {
                return CertificateQualification.ESig;
            }

            if (q.SuggestsQualifiedElectronicSeal)
            {
                return CertificateQualification.ESeal;
            }

            return CertificateQualification.Unknown;
        }

        if (signingCertificate is not null
            && SignerCertificateQualificationHeuristics.TryReadEtsiQcStatements(signingCertificate, out var f))
        {
            if (f.QcCompliance && f.Esign && f.Eseal)
            {
                return f.QcSscd ? CertificateQualification.QcQscdUnknown : CertificateQualification.QcUnknown;
            }

            if (f.QcCompliance && f.Esign && !f.Eseal)
            {
                return f.QcSscd ? CertificateQualification.QcQscdESig : CertificateQualification.QcESig;
            }

            if (f.QcCompliance && f.Eseal && !f.Esign)
            {
                return f.QcSscd ? CertificateQualification.QcQscdESeal : CertificateQualification.QcESeal;
            }

            if (f.Esign && !f.Eseal)
            {
                return CertificateQualification.ESig;
            }

            if (f.Eseal && !f.Esign)
            {
                return CertificateQualification.ESeal;
            }
        }

        return CertificateQualification.Unknown;
    }

    /// <summary>Estimates timestamp qualification for reporting.</summary>
    /// <remarks>
    /// Returns <see cref="TimestampQualification.QTsa"/> when the validation run succeeded, a signature-level
    /// timestamp check succeeded (imprint or CMS per policy), and the matched TSA TSL service is recognised as a
    /// <em>qualified time-stamping service</em> (ETSI <c>TSA/QTST</c>) with a granted-equivalent status
    /// (see <see cref="TslQualificationIndicators.SuggestsQualifiedTimestampService"/> /
    /// <see cref="TslQualificationIndicators.ServiceStatusIsGranted"/>). Otherwise returns
    /// <see cref="TimestampQualification.Tsa"/> when CMS or imprint verification succeeded but no qualified-TSA
    /// trusted-list evidence is available.
    /// </remarks>
    public static TimestampQualification EstimateTimestampQualification(SignatureTrustPolicy policy, SignatureValidationResult result)
    {
        // Aligned with SignatureValidator: any TSA-related flag (CMS, PKIX, or any TSA-TSL gate) forces token inspection.
        // Bare imprint policy alone is still recognised because the imprint check itself is signature-level timestamp evidence.
        var wantSig = policy.RequiresTsaTokenInspection
            || policy.TimestampImprintPolicy == SignatureTimestampImprintPolicy.RequireWhenPresent;
        if (!wantSig)
        {
            return TimestampQualification.Unknown;
        }

        if (result.TsaSignerCmsValid != true && result.SignatureTimestampImprintValid != true)
        {
            return TimestampQualification.Unknown;
        }

        if (result.Success
            && result.TimestampAuthorityListedInTrustedList == true
            && result.TimestampAuthorityTrustedListQualificationIndicators is { } tsaInd
            && tsaInd.SuggestsQualifiedTimestampService
            && tsaInd.ServiceStatusIsGranted == true)
        {
            return TimestampQualification.QTsa;
        }

        return TimestampQualification.Tsa;
    }
}
