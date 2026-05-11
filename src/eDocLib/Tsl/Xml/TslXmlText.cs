using System.Globalization;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace eDocLib.Tsl.Xml;

/// <summary>
/// Whitespace / Base64 / dateTime helpers for ETSI TSL XML payloads (TS 119 612).
/// </summary>
/// <remarks>
/// Shared low-level primitive consumed by both <c>eDocLib.Trust.Tsl</c> orchestration and
/// <c>eDocLib.Validation</c> parsing. Lives outside both so neither module needs to depend on the other.
/// </remarks>
internal static class TslXmlText
{
    /// <summary>Removes ASCII whitespace (CR, LF, space, tab) from <paramref name="value"/> for Base64 inputs.</summary>
    public static string CollapseBase64Whitespace(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (var ch in value)
        {
            if (ch is not '\r' and not '\n' and not ' ' and not '\t')
            {
                sb.Append(ch);
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Parses an XML <c>dateTime</c> element value as UTC <see cref="DateTimeOffset"/>. Falls back to
    /// <see cref="XmlConvert.ToDateTimeOffset(string)"/> when invariant parsing fails. Empty/missing text returns <c>null</c>.
    /// </summary>
    public static DateTimeOffset? TryParseUtcDateTime(XElement? element)
    {
        if (element is null)
        {
            return null;
        }

        var v = element.Value.Trim();
        if (v.Length == 0)
        {
            return null;
        }

        if (DateTimeOffset.TryParse(
                v,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var dto))
        {
            return dto;
        }

        try
        {
            return XmlConvert.ToDateTimeOffset(v);
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
