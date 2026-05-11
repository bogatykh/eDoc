using System.Collections.Generic;

using eDocLib.Revocation;
using eDocLib.Revocation.Online;

namespace eDocLib.Validation;

/// <summary>Result of <see cref="ApplicationOnlineRevocation.TryVerifyIfRequiredAsync"/>.</summary>
internal readonly record struct OnlineRevocationOutcome(
    bool Ok,
    string? Error,
    RevocationMaterialFetchResult? Fetched,
    IReadOnlyList<RevocationArtifactOutcome>? Artifacts)
{
    /// <summary>Online revocation not used by policy (success, no network).</summary>
    public static OnlineRevocationOutcome SuccessNoFetch => new(true, null, null, null);

    /// <summary>Verification failed or fetch error; <paramref name="error"/> is human-readable.</summary>
    public static OnlineRevocationOutcome Failed(string error) => new(false, error, null, null);
}
