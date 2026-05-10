namespace eDocLib.Validation;

/// <summary>Service metadata from a TSL <c>TSPService/ServiceInformation</c> block for a certificate.</summary>
public sealed class TrustedListQualification
{
    /// <summary>ETSI <c>ServiceTypeIdentifier</c> URIs (e.g. CA/QC, QCertESign).</summary>
    public required IReadOnlyList<string> ServiceTypeIdentifiers { get; init; }

    /// <summary><c>ServiceStatus</c> URI from the same <c>ServiceInformation</c> block, when present.</summary>
    public string? ServiceStatusUri { get; init; }

    /// <summary>
    /// Prior type/status intervals from <c>TSPService/ServiceHistory</c> for this trust service (same <c>TSPService</c> as the listing certificate),
    /// oldest <see cref="TrustedListServiceHistorySnapshot.StatusStartingTime"/> first when times are present.
    /// </summary>
    public IReadOnlyList<TrustedListServiceHistorySnapshot>? ServiceHistory { get; init; }
}
