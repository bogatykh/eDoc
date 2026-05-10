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

        if (signature.UnsignedEncapsulatedArchiveTimeStampDer.Count > 0)
        {
            return SignatureProfile.ArchivedSignature;
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
                return CertificateQualification.QcUnknown;
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

    /// <summary>Estimates timestamp qualification.</summary>
    public static TimestampQualification EstimateTimestampQualification(SignatureTrustPolicy policy, SignatureValidationResult result)
    {
        var wantSig = policy.ValidateTsaSigner || policy.ValidateTsaSignerChain
            || policy.TimestampImprintPolicy == SignatureTimestampImprintPolicy.RequireWhenPresent;
        var wantArch = policy.ValidateArchiveTimeStampCms || policy.ValidateArchiveTimeStampChain
            || policy.ArchiveTimestampImprintPolicy == ArchiveTimestampImprintPolicy.RequireWhenPresent;
        if (!wantSig && !wantArch)
        {
            return TimestampQualification.Unknown;
        }

        if (result.TsaSignerCmsValid == true || result.SignatureTimestampImprintValid == true)
        {
            return TimestampQualification.Tsa;
        }

        if (result.ArchiveTimeStampCount > 0
            && (result.ArchiveTimeStampsCmsValid == true || result.ArchiveTimeStampImprintsValid == true))
        {
            return TimestampQualification.Tsa;
        }

        return TimestampQualification.Unknown;
    }
}
