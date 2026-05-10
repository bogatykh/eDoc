namespace eDocLib.Validation;

/// <summary>Whether an embedded XAdES-T signature-level timestamp imprint is verified during validation.</summary>
public enum SignatureTimestampImprintPolicy
{
    /// <summary>Do not verify RFC 3161 imprint against <c>SignatureValue</c>.</summary>
    Ignore = 0,

    /// <summary>
    /// If an XAdES-T <c>xades:SignatureTimeStamp</c> / <c>EncapsulatedTimeStamp</c> is present (not archive tokens),
    /// require a parseable RFC 3161 token whose SHA-256 imprint matches <c>SHA256(SignatureValue bytes)</c>.
    /// Pure XAdES-BES (no signature-level timestamp) remains valid.
    /// </summary>
    RequireWhenPresent = 1,
}
