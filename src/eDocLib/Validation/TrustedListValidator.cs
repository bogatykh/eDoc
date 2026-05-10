namespace eDocLib.Validation;

/// <summary>
/// EP-40: validates (optional XML-DSig) and parses a TS 119 612 trust service status list into a
/// <see cref="TrustedListServiceIndex"/>. Delegates to <see cref="TrustedListReader"/>; use for a single entry point
/// when naming alignment with TSL “validator” terminology matters.
/// </summary>
internal static class TrustedListValidator
{
    /// <summary>
    /// Verifies the TSL when <paramref name="verifyXmlSignature"/> is <c>true</c>, then builds the service index and scheme metadata.
    /// </summary>
    public static bool TryValidate(
        Stream tslXml,
        bool verifyXmlSignature,
        out TrustedListLoadResult? result,
        out string? error) =>
        TrustedListReader.TryLoadDocument(tslXml, verifyXmlSignature, out result, out error);
}
