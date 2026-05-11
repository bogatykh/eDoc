using System.Diagnostics.CodeAnalysis;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;

namespace eDocLib.Validation;

internal static partial class SignatureTimestampVerifier
{
    private static bool TryParseTimeStampToken(
        byte[] tokenDer,
        [NotNullWhen(true)] out TimeStampToken? token,
        out string? error)
    {
        token = null;
        error = null;
        try
        {
            token = new TimeStampToken(new CmsSignedData(tokenDer));
            return true;
        }
        catch (Exception ex) when (ex is TspException or CmsException)
        {
            error = "Failed to parse time-stamp token: " + ex.Message;
            return false;
        }
    }

    /// <summary>Parses the DER token and returns the SHA-256 message-imprint octets (RFC 3161).</summary>
    private static bool TryReadSha256MessageImprintFromDer(
        byte[] tokenDer,
        out byte[] hashedMessage,
        out string? error)
    {
        hashedMessage = [];
        if (!TryParseTimeStampToken(tokenDer, out var token, out error) || token is null)
        {
            return false;
        }

        return TryGetSha256MessageImprintBytes(token, out hashedMessage, out error);
    }

    private static bool TryGetSha256MessageImprintBytes(
        TimeStampToken token,
        out byte[] hashedMessage,
        out string? error)
    {
        hashedMessage = [];
        var info = token.TimeStampInfo;
        if (!string.Equals(info.MessageImprintAlgOid, TspAlgorithms.Sha256, StringComparison.Ordinal))
        {
            error = $"Time-stamp imprint uses algorithm {info.MessageImprintAlgOid}, expected {TspAlgorithms.Sha256}.";
            return false;
        }

        var hashed = info.TstInfo.MessageImprint.GetHashedMessage();
        if (hashed is null || hashed.Length == 0)
        {
            error = "Time-stamp message imprint is missing.";
            return false;
        }

        hashedMessage = hashed;
        error = null;
        return true;
    }
}
