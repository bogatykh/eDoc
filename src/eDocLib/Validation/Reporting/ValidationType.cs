namespace eDocLib.Validation.Reporting;

/// <summary>Identifies the semantic role of a node in <see cref="ValidationResultNode"/>.</summary>
public enum ValidationType
{
    /// <summary>Root validation node.</summary>
    Root,

    /// <summary>Container structure validation branch.</summary>
    Structure,

    /// <summary>Data object count check for an eDoc container.</summary>
    StructureEdocDataObjectCount,

    /// <summary>PDF page count check.</summary>
    StructurePdfPageCount,

    /// <summary>Signature count check.</summary>
    StructureSignatureCount,

    /// <summary>Single signature validation branch.</summary>
    Signature,

    /// <summary>Data object reference checks for an eDoc signature.</summary>
    SignatureEdocDataObjectReferences,

    /// <summary>Signing certificate reference checks for an eDoc signature.</summary>
    SignatureEdocSigningCertificateReferences,

    /// <summary>Signature method check.</summary>
    SignatureMethod,

    /// <summary>Signed attributes check for a PDF Adobe PKCS#7 detached signature.</summary>
    SignaturePdfAdobePkcs7DetachedSignedAttributes,

    /// <summary>Signed attributes check for a PDF ETSI CAdES detached signature.</summary>
    SignaturePdfEtsiCadesDetachedSignedAttributes,

    /// <summary>XAdES <c>SignatureProductionPlace</c> (informational).</summary>
    SignatureProductionPlace,

    /// <summary>Signature profile classification.</summary>
    SignatureProfile,

    /// <summary>Signer <c>ClaimedRole</c> policy / outcome when constraints apply.</summary>
    SignatureSignerClaimedRoles,

    /// <summary>Signing certificate validation branch.</summary>
    SignatureSigningCertificate,

    /// <summary>Signing certificate serial number check.</summary>
    SignatureSigningCertificateSerial,

    /// <summary>Signing certificate validity period check.</summary>
    SignatureSigningCertificateValidity,

    /// <summary>Not-before instant (UTC); child under <see cref="SignatureSigningCertificateValidity"/>.</summary>
    SignatureSigningCertificateNotBefore,

    /// <summary>Not-after instant (UTC); child under <see cref="SignatureSigningCertificateValidity"/>.</summary>
    SignatureSigningCertificateNotAfter,

    /// <summary>Non-<c>NoError</c> <see cref="System.Security.Cryptography.X509Certificates.X509ChainStatusFlags"/> for this chain element.</summary>
    SignatureSigningCertificatePkixStatuses,

    /// <summary>PKIX chain validation branch for the signing certificate.</summary>
    SignatureSigningCertificateChain,

    /// <summary>Legacy combined caption; prefer <see cref="SignatureRevocation"/> branch for new trees.</summary>
    SignatureSigningCertificateStatus,
    /// <summary>Revocation summary branch (PKIX mode, embedded unsigned material, application online fetch).</summary>
    SignatureRevocation,
    /// <summary>Effective <see cref="System.Security.Cryptography.X509Certificates.X509RevocationMode"/> used when the signing PKIX chain was built.</summary>
    SignatureRevocationPkixChainMode,
    /// <summary>Unsigned XAdES <c>RevocationValues</c> policy and outcome.</summary>
    SignatureRevocationEmbeddedUnsigned,
    /// <summary>Application-controlled OCSP/CRL fetch after chain build.</summary>
    SignatureRevocationApplicationOnline,
    /// <summary>Single OCSP or CRL blob under embedded unsigned <c>RevocationValues</c> (child when detailed outcomes exist).</summary>
    SignatureRevocationEmbeddedUnsignedArtifact,
    /// <summary>Single OCSP or CRL blob from application-controlled online fetch (child when detailed outcomes exist).</summary>
    SignatureRevocationApplicationOnlineArtifact,

    /// <summary>Signature timestamp validation branch.</summary>
    SignatureTimestamp,

    /// <summary>Timestamp signing certificate validation branch.</summary>
    SignatureTimestampCertificate,

    /// <summary>PKIX path for the TSA signing certificate when <see cref="SignatureTrustPolicy.ValidateTsaSignerChain"/> runs.</summary>
    SignatureTimestampCertificateChain,

    /// <summary>Timestamp token CMS signature check.</summary>
    SignatureTimestampSignature,
    /// <summary>Archive time-stamp subtree (CMS + optional TSA chain).</summary>
    SignatureArchiveTimeStamp,
    /// <summary>RFC 3161 archive token CMS verification.</summary>
    SignatureArchiveTimeStampSignature,
    /// <summary>PKIX validation for archive TSA certificate when enabled.</summary>
    SignatureArchiveTimeStampCertificate,
    /// <summary>Archive RFC 3161 message imprint vs default signature XML digest input.</summary>
    SignatureArchiveTimeStampImprint,

    /// <summary>Signature type classification.</summary>
    SignatureType,

    /// <summary>Signature value verification check.</summary>
    SignatureValue,
}
