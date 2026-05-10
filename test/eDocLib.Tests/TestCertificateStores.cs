using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace eDocLib;

/// <summary>Minimal <see cref="IStore{T}"/> for CMS test helpers.</summary>
internal sealed class CertificateListStore : IStore<X509Certificate>
{
    private readonly List<X509Certificate> _certs;

    public CertificateListStore(IEnumerable<X509Certificate> certs) =>
        _certs = certs.ToList();

    public IEnumerable<X509Certificate> EnumerateMatches(ISelector<X509Certificate>? selector)
    {
        foreach (var c in _certs)
        {
            if (selector == null || selector.Match(c))
            {
                yield return c;
            }
        }
    }
}

internal sealed class EmptyCrlListStore : IStore<X509Crl>
{
    public IEnumerable<X509Crl> EnumerateMatches(ISelector<X509Crl>? selector) =>
        Enumerable.Empty<X509Crl>();
}
