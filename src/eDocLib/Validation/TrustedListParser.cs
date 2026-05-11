namespace eDocLib.Validation;

/// <summary>
/// EP-40: parses TS 119 612 XML into <see cref="TrustedListLoadResult"/> (same behaviour as <see cref="TrustedListReader"/> /
/// <see cref="TrustedListValidator"/>).
/// </summary>
internal static class TrustedListParser
{
    /// <inheritdoc cref="TrustedListReader.TryLoadDocument(Stream, bool, out TrustedListLoadResult?, out string?)"/>
    public static bool TryParse(
        Stream tslXml,
        bool verifyXmlSignature,
        out TrustedListLoadResult? result,
        out string? error) =>
        TrustedListReader.TryLoadDocument(tslXml, verifyXmlSignature, out result, out error);
}
