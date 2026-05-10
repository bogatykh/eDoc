using eDocLib.Timestamp;

namespace eDocLib.Configuration;

/// <summary>Optional defaults aligned with <see cref="eDocLib.Validation.SignatureTrustPolicy"/> online revocation fields.</summary>
public sealed class EdocLibOnlineRevocationSettings
{
    /// <summary>
    /// When <c>true</c>, after a successful base CRL fetch from CDP, also attempt a delta CRL from the base CRL’s Freshest CRL extension (RFC 5280).
    /// </summary>
    public bool FetchDeltaCrlViaFreshestCdp { get; set; }
}

/// <summary>Maps a SHA-1 certificate thumbprint to an RFC 3161 HTTP endpoint.</summary>
public sealed class EdocLibTimestampRoute
{
    /// <summary><c>issuerThumbprint</c> or <c>endEntityThumbprint</c> (see <see cref="TimestampResponderRegistry"/>).</summary>
    public string Kind { get; set; } = "";

    /// <summary>SHA-1 thumbprint in hexadecimal (with or without separators), matched after normalization.</summary>
    public string ThumbprintSha1Hex { get; set; } = "";

    /// <summary>Absolute HTTP(S) URI of the RFC 3161 time-stamp endpoint.</summary>
    public string HttpEndpoint { get; set; } = "";
}
