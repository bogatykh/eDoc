namespace eDocLib.Validation;

/// <summary>
/// Successful parse of a TS 119 612 <c>TrustServiceStatusList</c>: PKIX-oriented service index plus scheme metadata.
/// </summary>
public sealed record TrustedListLoadResult(
    TrustedListServiceIndex Index,
    TrustedListDocumentMetadata DocumentMetadata);
