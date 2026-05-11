using System.Security.Cryptography.X509Certificates;

namespace eDocLib;

/// <summary>Reusable building blocks for <see cref="X509Chain"/> configuration and result formatting.</summary>
internal static class X509ChainBuildHelpers
{
    /// <summary>
    /// When <paramref name="anchors"/> has any non-null entry, switches <see cref="X509ChainPolicy.TrustMode"/> to
    /// <see cref="X509ChainTrustMode.CustomRootTrust"/> and populates <see cref="X509ChainPolicy.CustomTrustStore"/>.
    /// </summary>
    public static void ApplyTrustAnchors(X509ChainPolicy policy, IEnumerable<X509Certificate2>? anchors)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (anchors is null)
        {
            return;
        }

        var added = false;
        foreach (var anchor in anchors)
        {
            if (anchor is null)
            {
                continue;
            }

            if (!added)
            {
                policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                added = true;
            }

            policy.CustomTrustStore.Add(anchor);
        }
    }

    /// <summary>Appends each non-null certificate in <paramref name="extras"/> to <see cref="X509ChainPolicy.ExtraStore"/>.</summary>
    public static void ApplyExtraStore(X509ChainPolicy policy, IEnumerable<X509Certificate2>? extras)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (extras is null)
        {
            return;
        }

        foreach (var c in extras)
        {
            if (c is null)
            {
                continue;
            }

            policy.ExtraStore.Add(c);
        }
    }

    /// <summary>
    /// Joins trimmed <see cref="X509ChainStatus.StatusInformation"/> with <c>"; "</c>, or returns
    /// <c>"Unknown chain error."</c> when no entries are present.
    /// </summary>
    public static string FormatChainStatus(X509Chain chain)
    {
        ArgumentNullException.ThrowIfNull(chain);
        if (chain.ChainStatus.Length == 0)
        {
            return "Unknown chain error.";
        }

        return string.Join("; ", chain.ChainStatus.Select(s => s.StatusInformation.Trim()));
    }

    /// <summary>Materialises <see cref="X509Chain.ChainElements"/> as a leaf-to-root array of certificates.</summary>
    public static X509Certificate2[] ToCertificatePath(X509Chain chain)
    {
        ArgumentNullException.ThrowIfNull(chain);
        var path = new X509Certificate2[chain.ChainElements.Count];
        for (var i = 0; i < chain.ChainElements.Count; i++)
        {
            path[i] = chain.ChainElements[i].Certificate;
        }

        return path;
    }
}
