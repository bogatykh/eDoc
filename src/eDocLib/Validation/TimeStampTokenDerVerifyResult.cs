using System.Collections.Generic;

namespace eDocLib.Validation;

/// <summary>Outcome of <see cref="SignatureTimestampVerifier.TryVerifyTimeStampTokenDerAsync"/>.</summary>
internal readonly record struct TimeStampTokenDerVerifyResult(
    bool Ok,
    string? Error,
    bool? CmsValid,
    bool? ChainValid,
    IReadOnlyList<CertificateChainDiagnostic>? CertificateChain)
{
    public static TimeStampTokenDerVerifyResult Success(bool? cmsValid, bool? chainValid, IReadOnlyList<CertificateChainDiagnostic>? chain) =>
        new(true, null, cmsValid, chainValid, chain);

    public static TimeStampTokenDerVerifyResult Fail(string error, bool? cmsValid, bool? chainValid, IReadOnlyList<CertificateChainDiagnostic>? chain) =>
        new(false, error, cmsValid, chainValid, chain);
}
