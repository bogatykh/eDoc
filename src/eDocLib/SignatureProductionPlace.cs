namespace eDocLib;

/// <summary>
/// Optional <c>SignatureProductionPlace</c> metadata attached to a detached signature
/// (claimed location of the signer at signing time, per ETSI EN 319 132 for XAdES).
/// All fields are independent and may be <c>null</c>; presence and meaning are signer-asserted.
/// </summary>
public sealed record SignatureProductionPlace(
    string? City = null,
    string? StateOrProvince = null,
    string? PostalCode = null,
    string? CountryName = null);
