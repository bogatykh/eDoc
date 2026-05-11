using System.Diagnostics.CodeAnalysis;
using System.Xml.Linq;
using eDocLib.Tsl.Xml;

namespace eDocLib.Trust.Tsl;

/// <summary>
/// Extracts national TSL download URLs from the EU List of Trusted Lists (ETSI TS 119 612 XML).
/// </summary>
internal static class EuLotlPointerLocator
{
    /// <summary>ETSI TSL namespace alias.</summary>
    private static readonly XNamespace TslNs = TslXmlNamespace.Tsl;

    /// <summary>One <c>OtherTSLPointer</c> row from an EU LOTL document.</summary>
    /// <param name="SchemeTerritory">Usually ISO 3166-1 alpha-2.</param>
    /// <param name="TsLocation">Publication URL for the national trust service list.</param>
    internal readonly record struct EuLotlNationalPointer(string SchemeTerritory, string TsLocation);

    /// <summary>
    /// Enumerates all <c>SchemeTerritory</c> / <c>TSLLocation</c> pairs under <c>OtherTSLPointer</c> elements (order follows XML).
    /// </summary>
    /// <param name="euLotlXml">EU LOTL XML stream (read once).</param>
    public static IReadOnlyList<EuLotlNationalPointer> EnumerateNationalPointers(Stream euLotlXml)
    {
        ArgumentNullException.ThrowIfNull(euLotlXml);
        return EnumerateNationalPointersCore(euLotlXml).ToList();
    }

    /// <summary>
    /// Finds <c>TSLLocation</c> under <c>OtherTSLPointer</c> whose <c>SchemeTerritory</c> matches <paramref name="territory"/>.
    /// </summary>
    /// <param name="euLotlXml">Stream of EU LOTL XML; must be seekable if the caller will reuse it.</param>
    /// <param name="territory">ISO 3166-1 alpha-2 territory (e.g. LV).</param>
    /// <param name="tslLocation">Matching national TSL URL when found.</param>
    public static bool TryGetNationalTslUrl(Stream euLotlXml, string territory, [NotNullWhen(true)] out string? tslLocation)
    {
        ArgumentNullException.ThrowIfNull(euLotlXml);
        ArgumentException.ThrowIfNullOrWhiteSpace(territory);

        tslLocation = null;
        var t = territory.Trim();
        if (t.Length != 2)
            return false;

        foreach (var row in EnumerateNationalPointersCore(euLotlXml))
        {
            if (string.Equals(row.SchemeTerritory, t, StringComparison.Ordinal))
            {
                tslLocation = row.TsLocation;
                return true;
            }
        }

        return false;
    }

    private static IEnumerable<EuLotlNationalPointer> EnumerateNationalPointersCore(Stream euLotlXml)
    {
        var doc = XDocument.Load(euLotlXml, LoadOptions.PreserveWhitespace);
        foreach (var pointer in doc.Descendants(TslNs + "OtherTSLPointer"))
        {
            var schemeTerritory = pointer
                .Elements(TslNs + "AdditionalInformation")
                .Elements(TslNs + "OtherInformation")
                .Elements(TslNs + "SchemeTerritory")
                .Select(e => e.Value.Trim())
                .FirstOrDefault();

            var loc = pointer.Element(TslNs + "TSLLocation")?.Value.Trim();
            if (string.IsNullOrEmpty(schemeTerritory) || string.IsNullOrEmpty(loc))
            {
                continue;
            }

            yield return new EuLotlNationalPointer(schemeTerritory, loc);
        }
    }
}
