using Org.BouncyCastle.Ocsp;

namespace eDocLib.Revocation.Protocols.Ocsp;

/// <summary>Centralized <see cref="OcspResp"/> / <see cref="BasicOcspResp"/> parsing for internal facades.</summary>
internal static class OcspResponseInternals
{
    /// <summary>Parses DER as <see cref="OcspResp"/>.</summary>
    internal static bool TryParse(byte[] der, out OcspResp? resp, out string? error)
    {
        ArgumentNullException.ThrowIfNull(der);
        resp = null;
        error = null;
        try
        {
            resp = new OcspResp(der);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    /// <summary>Requires <see cref="OcspRespStatus.Successful"/> and a <see cref="BasicOcspResp"/> payload.</summary>
    internal static bool TryGetSuccessfulBasic(byte[] der, out BasicOcspResp? basic, out string? error)
    {
        basic = null;
        error = null;
        if (!TryParse(der, out var resp, out error))
        {
            return false;
        }

        try
        {
            if (resp!.Status != OcspRespStatus.Successful)
            {
                error = $"OCSP transport status is {resp.Status}, expected {OcspRespStatus.Successful}.";
                return false;
            }

            if (resp.GetResponseObject() is not BasicOcspResp b)
            {
                error = "OCSP response does not contain BasicOCSPResponse.";
                return false;
            }

            basic = b;
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }
}
