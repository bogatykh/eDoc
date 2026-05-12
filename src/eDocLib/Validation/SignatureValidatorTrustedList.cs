using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace eDocLib.Validation;

/// <summary>Trusted-list checks for <see cref="SignatureValidator"/>.</summary>
internal static class SignatureValidatorTrustedList
{
    internal readonly record struct Evaluation(
        bool Ok,
        string? Error,
        bool? Listed,
        IReadOnlyList<string>? ServiceTypeIds,
        string? ServiceStatus);

    internal static Evaluation Evaluate(SignatureTrustPolicy policy, X509Certificate2? signingCert)
    {
        if (policy.TrustedListServiceIndex is null)
            return new Evaluation(true, null, null, null, null);

        if (signingCert is null)
        {
            if (policy.RequireSigningCertificateListedInTrustedList)
            {
                return new Evaluation(
                    false,
                    "Signing certificate is required for trusted list qualification but was not found in the signature.",
                    null,
                    null,
                    null);
            }

            return new Evaluation(true, null, null, null, null);
        }

        if (policy.TrustedListServiceIndex.TryGetQualification(signingCert, out var q))
        {
            if (policy.TrustedListQualificationReferenceTimeUtc is { } refUtc)
            {
                q = TrustedListQualificationResolver.ResolveEffectiveQualification(q, refUtc);
            }

            return new Evaluation(true, null, true, q.ServiceTypeIdentifiers, q.ServiceStatusUri);
        }

        if (policy.RequireSigningCertificateListedInTrustedList)
        {
            return new Evaluation(
                false,
                "Signing certificate is not listed in the configured trusted service list.",
                false,
                null,
                null);
        }

        return new Evaluation(true, null, false, null, null);
    }

    /// <summary>Maps signer TSL rows to qualification indicators when <see cref="Evaluation.Listed"/> is <c>true</c>.</summary>
    internal static TslQualificationIndicators? SignerQualificationIndicators(SignatureTrustPolicy policy, Evaluation tsl) =>
        tsl.Listed == true
            ? TslQualificationMapper.Map(tsl.ServiceTypeIds, tsl.ServiceStatus, policy.ResolveQualificationMappingOptions())
            : null;
}
