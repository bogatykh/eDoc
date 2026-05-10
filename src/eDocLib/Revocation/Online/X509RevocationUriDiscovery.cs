using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using eDocLib.Revocation.Protocols.Der;

namespace eDocLib.Revocation.Online;

/// <summary>Extracts HTTP(S) OCSP and CRL distribution URIs from X.509 extensions (AIA, CDP) and from a CRL’s Freshest CRL extension.</summary>
internal static class X509RevocationUriDiscovery
{
    /// <summary>OCSP access method OID id-ad-ocsp (1.3.6.1.5.5.7.48.1).</summary>
    public const string OcspAccessMethodOid = "1.3.6.1.5.5.7.48.1";

    /// <summary>Returns the first HTTP or HTTPS OCSP responder URI from Authority Information Access, if any.</summary>
    public static bool TryGetOcspHttpUri(X509Certificate2 certificate, out Uri? ocspUri)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ocspUri = null;
        foreach (var s in GetOcspHttpUriStrings(certificate))
        {
            if (Uri.TryCreate(s, UriKind.Absolute, out var u) && (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps))
            {
                ocspUri = u;
                return true;
            }
        }

        return false;
    }

    /// <summary>All OCSP URIs from AIA (typically at most one HTTP(S) in practice).</summary>
    public static IReadOnlyList<string> GetOcspHttpUriStrings(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var cert = X509DerReaders.ReadCertificate(certificate.RawData);
        var raw = cert.GetExtensionValue(X509Extensions.AuthorityInfoAccess);
        if (raw == null)
        {
            return [];
        }

        var list = new List<string>();
        Asn1Object obj;
        try
        {
            obj = Asn1Object.FromByteArray(raw.GetOctets());
        }
        catch (Exception)
        {
            return [];
        }

        if (obj is not Asn1Sequence seq)
        {
            return [];
        }

        for (var i = 0; i < seq.Count; i++)
        {
            if (seq[i] is not Asn1Sequence pair || pair.Count < 2)
            {
                continue;
            }

            if (pair[0] is not DerObjectIdentifier method)
            {
                continue;
            }

            if (!string.Equals(method.Id, OcspAccessMethodOid, StringComparison.Ordinal))
            {
                continue;
            }

            // accessLocation is a CHOICE; production certs often encode it as a tagged GeneralName.
            var gn = pair[1] is Asn1TaggedObject taggedLoc
                ? GeneralName.GetInstance(taggedLoc)
                : GeneralName.GetInstance(pair[1]);
            if (gn.TagNo == GeneralName.UniformResourceIdentifier)
            {
                var s = DerIA5String.GetInstance(gn.Name).GetString();
                if (!string.IsNullOrWhiteSpace(s))
                {
                    list.Add(s.Trim());
                }
            }
        }

        return list;
    }

    /// <summary>HTTP(S) URIs from CRL Distribution Points (fullName URIs only).</summary>
    public static IReadOnlyList<Uri> GetCrlHttpUris(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var cert = X509DerReaders.ReadCertificate(certificate.RawData);
        var raw = cert.GetExtensionValue(X509Extensions.CrlDistributionPoints);
        if (raw == null)
        {
            return [];
        }

        return CollectHttpUrisFromCrlDistPointOctets(raw.GetOctets());
    }

    /// <summary>
    /// HTTP(S) URIs from a CRL’s Freshest CRL extension (RFC 5280); same <c>CRLDistributionPoints</c> structure as certificate CDP (fullName URIs only).
    /// </summary>
    public static IReadOnlyList<Uri> GetFreshestCrlHttpUris(byte[] crlDer)
    {
        ArgumentNullException.ThrowIfNull(crlDer);
        if (crlDer.Length == 0)
        {
            return [];
        }

        X509Crl crl;
        try
        {
            crl = X509DerReaders.ReadCrl(crlDer);
        }
        catch (Exception)
        {
            return [];
        }

        var raw = crl.GetExtensionValue(X509Extensions.FreshestCrl);
        if (raw == null)
        {
            return [];
        }

        return CollectHttpUrisFromCrlDistPointOctets(raw.GetOctets());
    }

    /// <summary>Collects HTTP URIs from CRL dist point octets.</summary>
    private static IReadOnlyList<Uri> CollectHttpUrisFromCrlDistPointOctets(byte[] extensionValueOctets)
    {
        Asn1Object obj;
        try
        {
            obj = Asn1Object.FromByteArray(extensionValueOctets);
        }
        catch (Exception)
        {
            return [];
        }

        // Extension values are OCTET STRINGs in X.509; some producers wrap the CRLDistributionPoints ASN.1 again as OCTET STRING.
        if (obj is Asn1OctetString nested)
        {
            try
            {
                obj = Asn1Object.FromByteArray(nested.GetOctets());
            }
            catch (Exception)
            {
                return [];
            }
        }

        if (CrlDistPoint.GetInstance(obj) is not { } cdp)
        {
            return [];
        }

        var uris = new List<Uri>();
        foreach (DistributionPoint dp in cdp.GetDistributionPoints())
        {
            var dpn = dp.DistributionPointName;
            if (dpn == null || dpn.Type != DistributionPointName.FullName)
            {
                continue;
            }

            var names = GeneralNames.GetInstance(dpn.Name);
            foreach (GeneralName gn in names.GetNames())
            {
                if (gn.TagNo != GeneralName.UniformResourceIdentifier)
                {
                    continue;
                }

                var s = DerIA5String.GetInstance(gn.Name).GetString();
                if (string.IsNullOrWhiteSpace(s))
                {
                    continue;
                }

                if (Uri.TryCreate(s.Trim(), UriKind.Absolute, out var u)
                    && (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps))
                {
                    uris.Add(u);
                }
            }
        }

        return uris;
    }
}
