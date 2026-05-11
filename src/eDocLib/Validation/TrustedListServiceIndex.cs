using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using eDocLib.Trust.Tsl;

namespace eDocLib.Validation;

/// <summary>
/// Maps signing-certificate thumbprints to current <c>ServiceInformation</c> in an ETSI TSL (TS 119 612),
/// plus optional <c>ServiceHistory</c> snapshots from the same <c>TSPService</c>.
/// </summary>
public sealed class TrustedListServiceIndex
{
    /// <summary>ETSI TSL namespace alias.</summary>
    private static readonly XNamespace TslNs = TslXmlNamespace.Tsl;

    /// <summary>Stores the by thumbprint.</summary>
    private readonly Dictionary<string, TrustedListQualification> _byThumbprint;

    /// <summary>Initializes a new trusted list service index instance.</summary>
    private TrustedListServiceIndex(Dictionary<string, TrustedListQualification> byThumbprint) =>
        _byThumbprint = byThumbprint;

    /// <summary>Creates a value from x document.</summary>
    public static TrustedListServiceIndex FromXDocument(XDocument doc)
    {
        ArgumentNullException.ThrowIfNull(doc);
        var mergedTypes = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        var statusByThumb = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var historyByThumb = new Dictionary<string, List<TrustedListServiceHistorySnapshot>>(StringComparer.OrdinalIgnoreCase);

        foreach (var tspService in doc.Descendants(TslNs + "TSPService"))
        {
            var svcInfo = tspService.Element(TslNs + "ServiceInformation");
            var historySnapshots = ParseServiceHistory(tspService);

            if (svcInfo is null)
            {
                continue;
            }

            var typeIds = svcInfo.Elements(TslNs + "ServiceTypeIdentifier")
                .Select(e => e.Value.Trim())
                .Where(s => s.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (typeIds.Count == 0)
            {
                continue;
            }

            var status = svcInfo.Element(TslNs + "ServiceStatus")?.Value.Trim();

            foreach (var certEl in svcInfo.Descendants(TslNs + "X509Certificate"))
            {
                var text = TslXmlText.CollapseBase64Whitespace(certEl.Value);
                if (text.Length == 0)
                {
                    continue;
                }

                byte[] raw;
                try
                {
                    raw = Convert.FromBase64String(text);
                }
                catch (FormatException)
                {
                    continue;
                }

                X509Certificate2 cert;
                try
                {
                    cert = new X509Certificate2(raw);
                }
                catch (CryptographicException)
                {
                    continue;
                }

                try
                {
                    var thumb = cert.Thumbprint;
                    if (!mergedTypes.TryGetValue(thumb, out var set))
                    {
                        set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        mergedTypes[thumb] = set;
                    }

                    foreach (var t in typeIds)
                    {
                        set.Add(t);
                    }

                    if (status is not null && !statusByThumb.ContainsKey(thumb))
                    {
                        statusByThumb[thumb] = status;
                    }

                    if (historySnapshots.Count > 0)
                    {
                        AppendHistorySnapshots(historyByThumb, thumb, historySnapshots);
                    }
                }
                finally
                {
                    cert.Dispose();
                }
            }
        }

        var dict = new Dictionary<string, TrustedListQualification>(StringComparer.OrdinalIgnoreCase);
        foreach (var (thumb, set) in mergedTypes)
        {
            historyByThumb.TryGetValue(thumb, out var histList);
            IReadOnlyList<TrustedListServiceHistorySnapshot>? hist =
                histList is { Count: > 0 } ? histList : null;

            dict[thumb] = new TrustedListQualification
            {
                ServiceTypeIdentifiers = set.OrderBy(s => s, StringComparer.OrdinalIgnoreCase).ToList(),
                ServiceStatusUri = statusByThumb.GetValueOrDefault(thumb),
                ServiceHistory = hist,
            };
        }

        return new TrustedListServiceIndex(dict);
    }

    /// <summary>Appends history snapshots.</summary>
    private static void AppendHistorySnapshots(
        Dictionary<string, List<TrustedListServiceHistorySnapshot>> historyByThumb,
        string thumb,
        IReadOnlyList<TrustedListServiceHistorySnapshot> snapshots)
    {
        if (!historyByThumb.TryGetValue(thumb, out var list))
        {
            list = new List<TrustedListServiceHistorySnapshot>();
            historyByThumb[thumb] = list;
        }

        foreach (var s in snapshots)
        {
            list.Add(s);
        }
    }

    /// <summary>Parses <c>TSPService/ServiceHistory/ServiceHistoryInstance</c> nodes.</summary>
    private static IReadOnlyList<TrustedListServiceHistorySnapshot> ParseServiceHistory(XContainer tspService)
    {
        var root = tspService.Element(TslNs + "ServiceHistory");
        if (root is null)
        {
            return Array.Empty<TrustedListServiceHistorySnapshot>();
        }

        var list = new List<TrustedListServiceHistorySnapshot>();
        foreach (var inst in root.Elements(TslNs + "ServiceHistoryInstance"))
        {
            var types = inst.Elements(TslNs + "ServiceTypeIdentifier")
                .Select(e => e.Value.Trim())
                .Where(s => s.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (types.Count == 0)
            {
                continue;
            }

            var status = inst.Element(TslNs + "ServiceStatus")?.Value.Trim();
            var timeEl = inst.Element(TslNs + "StatusStartingTime");

            list.Add(
                new TrustedListServiceHistorySnapshot
                {
                    ServiceTypeIdentifiers = types,
                    ServiceStatusUri = status,
                    StatusStartingTime = TryParseStatusStartingTime(timeEl),
                });
        }

        return list
            .OrderBy(s => s.StatusStartingTime ?? DateTimeOffset.MaxValue)
            .ThenBy(s => s.ServiceStatusUri ?? "", StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>Attempts to parse status starting time.</summary>
    private static DateTimeOffset? TryParseStatusStartingTime(XElement? el) => TslXmlText.TryParseUtcDateTime(el);

    /// <summary>Loads XML from a stream (whitespace may be normalized; use for indexing only, not for signature verification).</summary>
    public static TrustedListServiceIndex FromStream(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var doc = XDocument.Load(stream, LoadOptions.PreserveWhitespace);
        return FromXDocument(doc);
    }

    /// <summary>Looks up trusted-list qualification metadata for <paramref name="certificate"/> by thumbprint.</summary>
    /// <param name="certificate">Certificate to look up.</param>
    /// <param name="qualification">Qualification metadata when the certificate is listed.</param>
    public bool TryGetQualification(X509Certificate2 certificate, [NotNullWhen(true)] out TrustedListQualification? qualification)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return _byThumbprint.TryGetValue(certificate.Thumbprint, out qualification);
    }

    /// <summary>Thumbprints (hex) that have at least one <c>ServiceInformation</c> entry.</summary>
    public IReadOnlyCollection<string> ListedThumbprints => _byThumbprint.Keys;
}
