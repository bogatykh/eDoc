using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using eDocLib.Revocation;
using eDocLib.Revocation.Online;
using eDocLib.Asic.Xades;

namespace eDocLib.Revocation.Xades;

/// <summary>Combines revocation HTTP fetch with XAdES unsigned <c>RevocationValues</c> embedding.</summary>
internal static class XadesRevocationEmbedding
{
    /// <summary>
    /// Downloads OCSP/CRL via <see cref="CertificateRevocationMaterialFetcher"/> and appends to the signature.
    /// Returns <c>false</c> when nothing was downloaded (no AIA/CDP or unreachable CRLs with no OCSP).
    /// </summary>
    public static async Task<bool> TryAppendUnsignedRevocationFromNetworkAsync(
        XadesSignature signature,
        X509Certificate2 endEntity,
        X509Certificate2 issuer,
        HttpClient http,
        IRevocationDerCache? responseCache = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(endEntity);
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(http);

        var fetched = await CertificateRevocationMaterialFetcher.FetchAsync(
                endEntity,
                issuer,
                http,
                responseCache: responseCache,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        if (fetched.OcspResponses.Count == 0 && fetched.Crls.Count == 0)
        {
            return false;
        }

        XadesBesSigner.AppendUnsignedRevocationValues(signature, fetched.OcspResponses, fetched.Crls);
        return true;
    }
}
