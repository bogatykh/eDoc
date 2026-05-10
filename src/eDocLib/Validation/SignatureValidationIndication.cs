namespace eDocLib.Validation;

/// <summary>
/// Coarse validation outcome (aligned with ETSI EN 319 102-1 style indications; not a full DSS report).
/// </summary>
public enum SignatureValidationIndication
{
    /// <summary>Validation succeeded per current <see cref="SignatureTrustPolicy"/>.</summary>
    TotalPassed,

    /// <summary>Core XML-DSig checks failed (digest or signature value).</summary>
    TotalFailed,

    /// <summary>
    /// References and signature value verified, but overall <see cref="SignatureValidationResult.Success"/> is false
    /// (e.g. chain, TSL, timestamp policy).
    /// </summary>
    Indeterminate,
}

/// <summary>Maps <see cref="SignatureValidationResult"/> to a compact indication for UI or reporting.</summary>
internal static class SignatureValidationIndicationExtensions
{
    /// <summary>Gets indication.</summary>
    public static SignatureValidationIndication GetIndication(this SignatureValidationResult result)
    {
        if (result.Success)
        {
            return SignatureValidationIndication.TotalPassed;
        }

        if (!result.ReferencesAndSignatureValid)
        {
            return SignatureValidationIndication.TotalFailed;
        }

        return SignatureValidationIndication.Indeterminate;
    }
}
