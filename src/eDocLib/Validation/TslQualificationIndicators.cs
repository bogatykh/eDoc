namespace eDocLib.Validation;

/// <summary>
/// Heuristic view of TSL <c>ServiceTypeIdentifier</c> / <c>ServiceStatus</c> values (ETSI TS 119 612).
/// Does not by itself prove a legally qualified signature, seal, or time-stamp under eIDAS —
/// combine with PKIX, profile rules, and certificate content.
/// </summary>
/// <param name="SuggestsQualifiedElectronicSignature">
/// At least one TSL <c>ServiceTypeIdentifier</c> URI is recognised as a qualified-certificate-for-electronic-signature marker.
/// </param>
/// <param name="SuggestsQualifiedElectronicSeal">
/// At least one TSL <c>ServiceTypeIdentifier</c> URI is recognised as a qualified-certificate-for-electronic-seal marker.
/// </param>
/// <param name="SuggestsQualifiedTimestampService">
/// At least one TSL <c>ServiceTypeIdentifier</c> URI is recognised as a qualified time-stamping service marker
/// (eIDAS Article 42 / ETSI EN 319 421). Combine with <see cref="ServiceStatusIsGranted"/> for a granted-and-qualified
/// TSA.
/// </param>
/// <param name="ServiceStatusIsGranted">
/// Whether the TSL <c>ServiceStatus</c> URI is recognised as a granted-equivalent status. <c>null</c> when the status URI was not present.
/// </param>
public sealed record TslQualificationIndicators(
    bool SuggestsQualifiedElectronicSignature,
    bool SuggestsQualifiedElectronicSeal,
    bool SuggestsQualifiedTimestampService,
    bool? ServiceStatusIsGranted);
