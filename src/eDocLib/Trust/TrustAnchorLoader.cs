using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Security;

namespace eDocLib.Trust;

/// <summary>Loads trust anchors for <see cref="Validation.SignatureTrustPolicy.CustomTrustAnchors"/> from PEM text, PKCS#12 (<c>.pfx</c>/<c>.p12</c>), or JKS (<c>.jks</c>) keystores.</summary>
public static class TrustAnchorLoader
{
    /// <summary>Imports all PEM-encoded certificates (one or more <c>BEGIN CERTIFICATE</c> blocks).</summary>
    public static X509Certificate2Collection FromPem(ReadOnlySpan<char> pem)
    {
        var coll = new X509Certificate2Collection();
        coll.ImportFromPem(pem);
        return coll;
    }

    /// <summary>Loads PEM-encoded certificates from a file (one or more <c>BEGIN CERTIFICATE</c> blocks).</summary>
    public static X509Certificate2Collection FromPemFile(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        var text = File.ReadAllText(path);
        return FromPem(text);
    }

    /// <summary>
    /// Imports a PKCS#12 store (typically only public certificates used as anchors; private keys are ignored for trust).
    /// </summary>
    public static X509Certificate2Collection FromPfx(string path, string? password, X509KeyStorageFlags flags = X509KeyStorageFlags.EphemeralKeySet)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        var coll = new X509Certificate2Collection();
        coll.Import(path, password, flags);
        return coll;
    }

    /// <summary>
    /// Loads X.509 certificates from a JKS (<c>.jks</c>) keystore file (password may be empty).
    /// Trusted certificate entries are imported; for private-key entries, every certificate in the stored chain
    /// is imported (typically end-entity and intermediates, deduplicated by thumbprint).
    /// Private keys are ignored for PKIX trust-anchor use.
    /// </summary>
    public static X509Certificate2Collection FromJksFile(string path, string? storePassword)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        using var fs = File.OpenRead(path);
        return FromJks(fs, storePassword);
    }

    /// <summary>Loads trust anchors from a JKS stream.</summary>
    /// <inheritdoc cref="FromJksFile"/>
    public static X509Certificate2Collection FromJks(Stream jks, string? storePassword)
    {
        ArgumentNullException.ThrowIfNull(jks);
        if (jks.CanSeek)
        {
            jks.Position = 0;
        }

        var store = new JksStore();
        var pw = storePassword.AsSpan();
        store.Load(jks, pw);

        var coll = new X509Certificate2Collection();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var alias in store.Aliases)
        {
            if (store.IsCertificateEntry(alias))
            {
                TryAddCertificate(store.GetCertificate(alias), coll, seen);
            }
            else if (store.IsKeyEntry(alias))
            {
                var chain = store.GetCertificateChain(alias);
                if (chain is { Length: > 0 })
                {
                    foreach (var c in chain)
                    {
                        TryAddCertificate(c, coll, seen);
                    }
                }
                else
                {
                    TryAddCertificate(store.GetCertificate(alias), coll, seen);
                }
            }
        }

        return coll;
    }

    private static void TryAddCertificate(Org.BouncyCastle.X509.X509Certificate? bc, X509Certificate2Collection coll, HashSet<string> seenThumbprints)
    {
        if (bc is null)
        {
            return;
        }

        var c2 = new X509Certificate2(bc.GetEncoded());
        if (!seenThumbprints.Add(c2.Thumbprint))
        {
            c2.Dispose();
            return;
        }

        coll.Add(c2);
    }
}
