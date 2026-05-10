using Org.BouncyCastle.Ocsp;

namespace eDocLib.Revocation.Protocols.Ocsp;

/// <summary>Facades over <see cref="OcspResp"/> / <see cref="BasicOcspResp"/> (no signature or PKIX policy).</summary>
internal static class OcspResponseReader
{
    /// <summary>Parses the top-level <c>responseStatus</c> via <see cref="OcspResp"/> (integer code; compare to <see cref="OcspRespStatus.Successful"/>).</summary>
    public static bool TryGetTransportStatus(byte[] ocspResponseDer, out int status)
    {
        ArgumentNullException.ThrowIfNull(ocspResponseDer);
        status = 0;
        if (!OcspResponseInternals.TryParse(ocspResponseDer, out var resp, out _))
        {
            return false;
        }

        status = resp!.Status;
        return true;
    }

    /// <summary>True when <see cref="TryGetTransportStatus"/> succeeds and status equals <see cref="OcspRespStatus.Successful"/>.</summary>
    public static bool IsTransportSuccessful(byte[] ocspResponseDer) =>
        TryGetTransportStatus(ocspResponseDer, out var s) && s == OcspRespStatus.Successful;

    /// <summary>
    /// When transport status is successful and <c>responseBytes</c> hold a Basic OCSP response,
    /// returns one entry per <see cref="SingleResp"/>. Does not verify the response signature or nonce.
    /// </summary>
    public static bool TryReadBasicSingleResponses(byte[] ocspResponseDer, out IReadOnlyList<OcspSingleResponseEntry>? entries)
    {
        ArgumentNullException.ThrowIfNull(ocspResponseDer);
        entries = null;
        if (!OcspResponseInternals.TryGetSuccessfulBasic(ocspResponseDer, out var basic, out _))
        {
            return false;
        }

        try
        {
            var list = new List<OcspSingleResponseEntry>();
            foreach (var single in basic!.Responses)
            {
                var certStatus = single.GetCertStatus();
                OcspCertificateStatusKind kind;
                DateTimeOffset? revokedAt = null;
                if (certStatus == null)
                {
                    kind = OcspCertificateStatusKind.Good;
                }
                else if (certStatus is RevokedStatus rs)
                {
                    kind = OcspCertificateStatusKind.Revoked;
                    revokedAt = new DateTimeOffset(rs.RevocationTime.ToUniversalTime());
                }
                else if (certStatus is UnknownStatus)
                {
                    kind = OcspCertificateStatusKind.Unknown;
                }
                else
                {
                    kind = OcspCertificateStatusKind.Unknown;
                }

                var serial = single.GetCertID().SerialNumber.ToByteArrayUnsigned();
                list.Add(new OcspSingleResponseEntry((byte[])serial.Clone(), kind, revokedAt));
            }

            entries = list;
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }
}
