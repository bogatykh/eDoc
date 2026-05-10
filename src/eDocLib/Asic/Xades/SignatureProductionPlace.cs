namespace eDocLib.Asic.Xades;

/// <summary>XAdES <c>SignatureProductionPlace</c> (optional fields per EN 319 132).</summary>
public sealed record SignatureProductionPlace(
    string? City = null,
    string? StateOrProvince = null,
    string? PostalCode = null,
    string? CountryName = null);
