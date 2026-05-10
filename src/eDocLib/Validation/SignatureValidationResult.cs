namespace eDocLib.Validation;

/// <summary>Outcome of validating an XML signature against payload digests and optional PKIX / XAdES policies.</summary>
/// <remarks>
/// This type is a <c>record</c> for mechanical reuse (<c>with</c> expressions in the validator). Instances with the same
/// property values compare equal; use reference semantics only when retaining a specific instance identity matters.
/// </remarks>
public sealed record SignatureValidationResult
{
    /// <summary>Whether all checks required by the active policy passed.</summary>
    public bool Success { get; init; }

    /// <summary>Human-readable primary error when <see cref="Success"/> is <c>false</c>.</summary>
    public string? Error { get; init; }

    /// <summary>Whether XML reference digest and signature value verification passed.</summary>
    public bool ReferencesAndSignatureValid { get; init; }

    /// <summary>
    /// When <see cref="SignatureTrustPolicy.HasSignerClaimedRoleConstraints"/> is <c>true</c>: <c>true</c> if role constraints passed,
    /// <c>false</c> if they failed. <c>null</c> when constraints were not evaluated (for example cryptographic verification failed first).
    /// </summary>
    public bool? SignerClaimedRolesConstraintOk { get; init; }

    /// <summary>Whether signer certificate chain validation passed when it was attempted.</summary>
    public bool? CertificateChainValid { get; init; }

    /// <summary>
    /// When PKIX validation ran (<see cref="SignatureTrustPolicy.ValidateCertificateChain"/>): ordered path from signing certificate
    /// toward trust anchor (empty list is not used; <c>null</c> when chain build was not attempted).
    /// </summary>
    public IReadOnlyList<CertificateChainDiagnostic>? SignerCertificateChain { get; init; }

    /// <summary>
    /// When imprint policy required verification and an XAdES-T <c>xades:SignatureTimeStamp</c> was present: <c>true</c> if it matched;
    /// <c>false</c> if it was present but invalid. Otherwise <c>null</c> (not checked or no signature-level timestamp).
    /// </summary>
    public bool? SignatureTimestampImprintValid { get; init; }

    /// <summary>Whether RFC 3161 time-stamp CMS verification of the TSA signer succeeded (only set when policy requested TSA verification).</summary>
    public bool? TsaSignerCmsValid { get; init; }

    /// <summary>Whether PKIX chain validation for the TSA certificate succeeded (only when policy requested chain validation).</summary>
    public bool? TsaSignerChainValid { get; init; }

    /// <summary>
    /// When TSA PKIX validation ran (<see cref="SignatureTrustPolicy.ValidateTsaSignerChain"/>): path from TSA certificate toward trust anchor
    /// (for example after <see cref="System.Security.Cryptography.X509Certificates.X509Chain.Build(System.Security.Cryptography.X509Certificates.X509Certificate2)"/>), including when the build failed. Otherwise <c>null</c>.
    /// </summary>
    public IReadOnlyList<CertificateChainDiagnostic>? TsaSignerCertificateChain { get; init; }

    /// <summary>Count of <c>xades:ArchiveTimeStamp</c> tokens with decodable <c>EncapsulatedTimeStamp</c> DER when archive policy ran.</summary>
    public int ArchiveTimeStampCount { get; init; }

    /// <summary>
    /// When <see cref="SignatureTrustPolicy.ValidateArchiveTimeStampCms"/> ran and at least one archive token was present:
    /// <c>true</c> if every token passed CMS verification. Otherwise <c>null</c>.
    /// </summary>
    public bool? ArchiveTimeStampsCmsValid { get; init; }

    /// <summary>
    /// When <see cref="SignatureTrustPolicy.ValidateArchiveTimeStampChain"/> ran: <c>true</c> if every archive TSA chain built.
    /// Otherwise <c>null</c>.
    /// </summary>
    public bool? ArchiveTimeStampsChainValid { get; init; }

    /// <summary>
    /// When <see cref="SignatureTrustPolicy.ArchiveTimestampImprintPolicy"/> required imprint verification and at least one archive
    /// token was present: <c>true</c> if every imprint matched the reconstructed digest input. Otherwise <c>null</c>.
    /// </summary>
    public bool? ArchiveTimeStampImprintsValid { get; init; }

    /// <summary>
    /// When a <see cref="SignatureTrustPolicy.TrustedListServiceIndex"/> was configured: <c>true</c> if the signing certificate
    /// matched a listed service; <c>false</c> if the certificate was present but not listed; <c>null</c> if no index, no signing certificate, or not evaluated.
    /// </summary>
    public bool? SigningCertificateListedInTrustedList { get; init; }

    /// <summary><c>ServiceTypeIdentifier</c> URIs from the matching TSL <c>ServiceInformation</c>, when listed.</summary>
    public IReadOnlyList<string>? TrustedListServiceTypeIdentifiers { get; init; }

    /// <summary><c>ServiceStatus</c> URI from the matching TSL block, when listed.</summary>
    public string? TrustedListServiceStatus { get; init; }

    /// <summary>
    /// When the signing certificate was listed in TSL: mapped interpretation of service types and status (national / EURI URI mapping).
    /// </summary>
    public TslQualificationIndicators? TrustedListQualificationIndicators { get; init; }

    /// <summary>
    /// When <see cref="SignatureTrustPolicy.VerifyUnsignedRevocationWhenPresent"/> ran against embedded <c>RevocationValues</c>:
    /// <c>true</c> if verification passed, <c>false</c> if it failed. Otherwise <c>null</c>.
    /// </summary>
    public bool? UnsignedRevocationArtifactsValid { get; init; }

    /// <summary>
    /// When <see cref="SignatureTrustPolicy.UsesApplicationControlledOnlineRevocation"/> and PKIX chain build succeeded:
    /// <c>true</c> if HTTP OCSP/CRL fetch and verification ran (including intentional no-op for some self-signed paths). Otherwise <c>null</c>.
    /// </summary>
    public bool? ApplicationOnlineRevocationChecked { get; init; }

    /// <summary>
    /// When <see cref="ApplicationOnlineRevocationChecked"/> is <c>true</c>: <c>true</c> if revocation material validated, <c>false</c> if fetch or verification failed.
    /// </summary>
    public bool? ApplicationOnlineRevocationValid { get; init; }

    /// <summary>Revocation snapshot for reporting (see <see cref="RevocationValidationReport"/>).</summary>
    public RevocationValidationReport? Revocation { get; init; }
}
