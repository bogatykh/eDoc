using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib.Asic.Xades;

namespace eDocLib.Validation;

internal static partial class SignatureValidator
{
    private static void AddUnsignedCertificateValuesToExtraStore(XadesSignature signature, X509ChainPolicy chainPolicy)
    {
        foreach (var der in signature.UnsignedEncapsulatedX509Der)
        {
            try
            {
                chainPolicy.ExtraStore.Add(new X509Certificate2(der));
            }
            catch (CryptographicException)
            {
            }
        }

        foreach (var p7 in signature.UnsignedEncapsulatedPkcs7Der)
        {
            if (!X509Pkcs7CertificateBag.TryImportCertificates(p7, out var coll))
            {
                continue;
            }

            foreach (X509Certificate2 c in coll)
            {
                try
                {
                    chainPolicy.ExtraStore.Add(new X509Certificate2(c.RawData));
                }
                catch (CryptographicException)
                {
                }
            }
        }
    }

    private static bool TryValidateClaimedSignerRoles(
        SignatureTrustPolicy policy,
        XadesSignature signature,
        out string? error)
    {
        error = null;
        HashSet<string>? allowSet = null;
        var allow = policy.SignerClaimedRoleAllowList;
        if (allow is not null && allow.Count > 0)
        {
            allowSet = new HashSet<string>(StringComparer.Ordinal);
            foreach (var s in allow)
            {
                if (!string.IsNullOrWhiteSpace(s))
                {
                    allowSet.Add(s.Trim());
                }
            }

            if (allowSet.Count == 0)
            {
                allowSet = null;
            }
        }

        var nonEmptyRoles = new List<string>(signature.SignerRoles.Count);
        foreach (var r in signature.SignerRoles)
        {
            if (!string.IsNullOrWhiteSpace(r))
            {
                nonEmptyRoles.Add(r.Trim());
            }
        }

        if (policy.RequireAtLeastOneSignerClaimedRole && nonEmptyRoles.Count == 0)
        {
            error = "At least one non-empty xades:ClaimedRole is required.";
            return false;
        }

        if (allowSet is null)
        {
            return true;
        }

        foreach (var r in nonEmptyRoles)
        {
            if (!allowSet.Contains(r))
            {
                error = $"Claimed signer role '{r}' is not allowed by policy.";
                return false;
            }
        }

        return true;
    }
}
