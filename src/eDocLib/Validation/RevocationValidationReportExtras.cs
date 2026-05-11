using eDocLib.Revocation;
using eDocLib.Revocation.Online;

namespace eDocLib.Validation;

/// <summary>Helpers for <see cref="RevocationValidationReport"/> flags on edge-case PKIX paths.</summary>
internal static class RevocationValidationReportExtras
{
    internal static bool OnlineFetchSkippedSelfSignedShortChain(
        SignatureTrustPolicy policy,
        bool? applicationOnlineRevocationValid,
        RevocationMaterialFetchResult? onlineFetched) =>
        policy.UsesApplicationControlledOnlineRevocation
        && applicationOnlineRevocationValid == true
        && onlineFetched is null;
}
