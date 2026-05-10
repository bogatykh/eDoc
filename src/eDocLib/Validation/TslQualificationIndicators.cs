namespace eDocLib.Validation;

/// <summary>
/// Heuristic view of TSL <c>ServiceTypeIdentifier</c> / <c>ServiceStatus</c> values (ETSI TS 119 612).
/// Does not by itself prove a legally qualified signature under eIDAS — combine with PKIX, profile rules, and certificate content.
/// </summary>
public sealed record TslQualificationIndicators(
    bool SuggestsQualifiedElectronicSignature,
    bool SuggestsQualifiedElectronicSeal,
    bool? ServiceStatusIsGranted);
