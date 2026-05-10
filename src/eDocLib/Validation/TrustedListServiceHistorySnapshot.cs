namespace eDocLib.Validation;

/// <summary>
/// One <c>ServiceHistoryInstance</c> under <c>TSPService/ServiceHistory</c> (ETSI TS 119 612): prior service type/status window.
/// </summary>
public sealed class TrustedListServiceHistorySnapshot
{
    /// <summary><c>ServiceTypeIdentifier</c> URIs from that history row.</summary>
    public required IReadOnlyList<string> ServiceTypeIdentifiers { get; init; }

    /// <summary><c>ServiceStatus</c> URI when present.</summary>
    public string? ServiceStatusUri { get; init; }

    /// <summary><c>StatusStartingTime</c> when parseable.</summary>
    public DateTimeOffset? StatusStartingTime { get; init; }
}
