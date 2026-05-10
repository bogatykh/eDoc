using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using eDocLib.Revocation;
using eDocLib.Revocation.Online;

namespace eDocLib.Validation;

/// <summary>
/// Summary of revocation-related inputs and outcomes for one signature validation (PKIX mode, embedded XAdES material, optional HTTP fetch).
/// </summary>
/// <param name="EffectiveChainRevocationMode">
/// Revocation mode passed to <see cref="X509Chain"/> when <see cref="SignatureTrustPolicy.ValidateCertificateChain"/> ran and build was attempted.
/// <c>null</c> when no PKIX build ran (for example cryptographic failure first or chain validation disabled).
/// </param>
/// <param name="ApplicationOnlineConfigured"><see cref="SignatureTrustPolicy.UsesApplicationControlledOnlineRevocation"/> at validation time.</param>
/// <param name="ApplicationOnlineChecked">Mirror of <see cref="SignatureValidationResult.ApplicationOnlineRevocationChecked"/>.</param>
/// <param name="ApplicationOnlineValid">Mirror of <see cref="SignatureValidationResult.ApplicationOnlineRevocationValid"/>.</param>
/// <param name="OnlineFetchedOcspCount">Number of non-empty OCSP responses returned by the last application-controlled fetch.</param>
/// <param name="OnlineFetchedCrlCount">Number of non-empty CRL blobs returned by the last application-controlled fetch.</param>
/// <param name="EmbeddedVerificationPolicyEnabled"><see cref="SignatureTrustPolicy.VerifyUnsignedRevocationWhenPresent"/> at validation time.</param>
/// <param name="EmbeddedOcspArtifactCount">Count of OCSP blobs under unsigned <c>RevocationValues</c> (not necessarily verified).</param>
/// <param name="EmbeddedCrlArtifactCount">Count of CRL blobs under unsigned <c>RevocationValues</c> (not necessarily verified).</param>
/// <param name="EmbeddedRevocationValid">Mirror of <see cref="SignatureValidationResult.UnsignedRevocationArtifactsValid"/>.</param>
/// <param name="HasEmbeddedRevocationArtifacts"><c>true</c> when <paramref name="EmbeddedOcspArtifactCount"/> or <paramref name="EmbeddedCrlArtifactCount"/> is non-zero.</param>
/// <param name="HasNonEmptyOnlineFetchedRevocation"><c>true</c> when <paramref name="OnlineFetchedOcspCount"/> or <paramref name="OnlineFetchedCrlCount"/> is non-zero.</param>
/// <param name="ApplicationOnlineFetchSkippedForSelfSignedShortChain">
/// When <paramref name="ApplicationOnlineConfigured"/> is <c>true</c> and online revocation succeeded without HTTP material:
/// PKIX path was treated as a single self-signed end-entity (no issuer fetch). Otherwise <c>false</c>.
/// </param>
/// <param name="EmbeddedUnsignedArtifactOutcomes">Per-blob outcomes when embedded <c>RevocationValues</c> verification ran.</param>
/// <param name="OnlineFetchedArtifactOutcomes">Per-blob outcomes when application-controlled online fetch and verify ran.</param>
public sealed record RevocationValidationReport(
    X509RevocationMode? EffectiveChainRevocationMode,
    bool ApplicationOnlineConfigured,
    bool? ApplicationOnlineChecked,
    bool? ApplicationOnlineValid,
    int OnlineFetchedOcspCount,
    int OnlineFetchedCrlCount,
    bool EmbeddedVerificationPolicyEnabled,
    int EmbeddedOcspArtifactCount,
    int EmbeddedCrlArtifactCount,
    bool? EmbeddedRevocationValid,
    bool HasEmbeddedRevocationArtifacts,
    bool HasNonEmptyOnlineFetchedRevocation,
    bool ApplicationOnlineFetchSkippedForSelfSignedShortChain,
    IReadOnlyList<RevocationArtifactOutcome>? EmbeddedUnsignedArtifactOutcomes = null,
    IReadOnlyList<RevocationArtifactOutcome>? OnlineFetchedArtifactOutcomes = null)
{
    /// <summary>Creates value.</summary>
    internal static RevocationValidationReport Create(
        SignatureTrustPolicy policy,
        int embeddedOcspArtifactCount,
        int embeddedCrlArtifactCount,
        bool pkixChainWasBuilt,
        bool? applicationOnlineChecked,
        bool? applicationOnlineValid,
        RevocationMaterialFetchResult? onlineFetched,
        bool? embeddedRevocationValid,
        bool applicationOnlineFetchSkippedForSelfSignedShortChain = false,
        IReadOnlyList<RevocationArtifactOutcome>? embeddedUnsignedArtifactOutcomes = null,
        IReadOnlyList<RevocationArtifactOutcome>? onlineFetchedArtifactOutcomes = null)
    {
        X509RevocationMode? chainMode = null;
        if (pkixChainWasBuilt)
        {
            chainMode = policy.UsesApplicationControlledOnlineRevocation
                ? X509RevocationMode.NoCheck
                : policy.RevocationMode;
        }

        var ocspN = 0;
        var crlN = 0;
        if (onlineFetched is not null)
        {
            ocspN = CountNonEmpty(onlineFetched.OcspResponses);
            crlN = CountNonEmpty(onlineFetched.Crls);
        }

        var hasEmbedded = embeddedOcspArtifactCount > 0 || embeddedCrlArtifactCount > 0;
        var hasOnline = ocspN > 0 || crlN > 0;

        return new RevocationValidationReport(
            chainMode,
            policy.UsesApplicationControlledOnlineRevocation,
            applicationOnlineChecked,
            applicationOnlineValid,
            ocspN,
            crlN,
            policy.VerifyUnsignedRevocationWhenPresent,
            embeddedOcspArtifactCount,
            embeddedCrlArtifactCount,
            embeddedRevocationValid,
            hasEmbedded,
            hasOnline,
            applicationOnlineFetchSkippedForSelfSignedShortChain,
            embeddedUnsignedArtifactOutcomes,
            onlineFetchedArtifactOutcomes);
    }

    /// <summary>Counts non-empty revocation artifacts.</summary>
    private static int CountNonEmpty(IReadOnlyList<byte[]> blobs)
    {
        var n = 0;
        foreach (var b in blobs)
        {
            if (b is { Length: > 0 })
            {
                n++;
            }
        }

        return n;
    }
}
