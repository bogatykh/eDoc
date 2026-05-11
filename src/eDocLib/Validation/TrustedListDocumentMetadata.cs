using System.Globalization;
using System.Xml.Linq;
using eDocLib.Tsl.Xml;

namespace eDocLib.Validation;

/// <summary>
/// Selected TS 119 612 <c>SchemeInformation</c> fields from a <c>TrustServiceStatusList</c> document (audit / freshness).
/// </summary>
public sealed record TrustedListDocumentMetadata
{
    /// <summary><c>TSLSequenceNumber</c> when present and parseable.</summary>
    public long? TslSequenceNumber { get; init; }

    /// <summary><c>SchemeTerritory</c> (typically ISO 3166-1 alpha-2).</summary>
    public string? SchemeTerritory { get; init; }

    /// <summary><c>ListIssueDateTime</c> when parseable.</summary>
    public DateTimeOffset? ListIssueDateTime { get; init; }

    /// <summary>Scheduled next update instant when parseable (often under <c>NextUpdate</c>).</summary>
    public DateTimeOffset? NextUpdate { get; init; }

    /// <summary>ETSI TSL namespace alias.</summary>
    private static readonly XNamespace TslNs = TslXmlNamespace.Tsl;

    /// <summary>Parses scheme-level metadata when <c>SchemeInformation</c> exists.</summary>
    public static TrustedListDocumentMetadata FromXDocument(XDocument doc)
    {
        ArgumentNullException.ThrowIfNull(doc);
        var scheme = doc.Root?.Element(TslNs + "SchemeInformation");
        if (scheme is null)
        {
            return new TrustedListDocumentMetadata();
        }

        long? seq = null;
        var seqText = scheme.Element(TslNs + "TSLSequenceNumber")?.Value.Trim();
        if (!string.IsNullOrEmpty(seqText) && long.TryParse(seqText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seqVal))
        {
            seq = seqVal;
        }

        var territory = scheme.Element(TslNs + "SchemeTerritory")?.Value.Trim();
        if (territory?.Length == 0)
        {
            territory = null;
        }

        var issue = ParseDateTimeElement(scheme.Element(TslNs + "ListIssueDateTime"));
        var next = ParseNextUpdate(scheme.Element(TslNs + "NextUpdate"));

        return new TrustedListDocumentMetadata
        {
            TslSequenceNumber = seq,
            SchemeTerritory = territory,
            ListIssueDateTime = issue,
            NextUpdate = next,
        };
    }

    /// <summary>Parses next update.</summary>
    private static DateTimeOffset? ParseNextUpdate(XElement? nextEl)
    {
        if (nextEl is null)
        {
            return null;
        }

        var inner = nextEl.Element(TslNs + "dateTime") ?? nextEl.Element(nextEl.Name.Namespace + "dateTime");
        return ParseDateTimeElement(inner ?? nextEl);
    }

    /// <summary>Parses date time element.</summary>
    private static DateTimeOffset? ParseDateTimeElement(XElement? el) => TslXmlText.TryParseUtcDateTime(el);
}
