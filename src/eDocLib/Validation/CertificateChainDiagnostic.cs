using System.Security.Cryptography.X509Certificates;

namespace eDocLib.Validation;

/// <summary>One element in the PKIX path built for the signing certificate.</summary>
public sealed record CertificateChainDiagnostic(
    int Index,
    string Subject,
    string Issuer,
    string Thumbprint,
    string SerialNumberHex,
    DateTimeOffset NotBeforeUtc,
    DateTimeOffset NotAfterUtc,
    IReadOnlyList<X509ChainStatus> ElementStatuses);

/// <summary>Maps <see cref="X509Chain"/> after <see cref="X509Chain.Build"/> to a flat ordered list (end-entity first).</summary>
internal static class CertificateChainDiagnostics
{
    /// <summary>Maps PKIX chain elements to diagnostics (end-entity first).</summary>
    public static IReadOnlyList<CertificateChainDiagnostic>? FromChain(X509Chain chain)
    {
        ArgumentNullException.ThrowIfNull(chain);
        if (chain.ChainElements.Count == 0)
        {
            return null;
        }

        var list = new List<CertificateChainDiagnostic>(chain.ChainElements.Count);
        for (var i = 0; i < chain.ChainElements.Count; i++)
        {
            var el = chain.ChainElements[i];
            var cert = el.Certificate;
            list.Add(new CertificateChainDiagnostic(
                i,
                cert.Subject,
                cert.Issuer,
                cert.Thumbprint,
                SerialNumberHex: FormatSerial(cert),
                NotBeforeUtc: new DateTimeOffset(cert.NotBefore.ToUniversalTime()),
                NotAfterUtc: new DateTimeOffset(cert.NotAfter.ToUniversalTime()),
                el.ChainElementStatus.ToArray()));
        }

        return list;
    }

    /// <summary>Formats serial.</summary>
    private static string FormatSerial(X509Certificate2 cert) =>
        cert.SerialNumber.Replace(" ", "", StringComparison.Ordinal).ToLowerInvariant();
}
