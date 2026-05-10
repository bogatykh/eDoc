using System.Security.Cryptography.X509Certificates;

namespace eDocLib.Validation;

/// <summary>
/// Aggregates element-level <see cref="X509ChainStatus"/> flags from <see cref="CertificateChainDiagnostic"/> paths (RFC 5280 PKIX context).
/// </summary>
internal static class CertificatePathStatus
{
    /// <summary>
    /// <c>true</c> when every element lists only <see cref="X509ChainStatusFlags.NoError"/>;
    /// <c>false</c> when any other flag appears; <c>null</c> when <paramref name="path"/> is null or empty.
    /// </summary>
    public static bool? AllElementsNoError(IReadOnlyList<CertificateChainDiagnostic>? path)
    {
        if (path is null || path.Count == 0)
        {
            return null;
        }

        foreach (var el in path)
        {
            foreach (var st in el.ElementStatuses)
            {
                if (st.Status != X509ChainStatusFlags.NoError)
                {
                    return false;
                }
            }
        }

        return true;
    }
}
