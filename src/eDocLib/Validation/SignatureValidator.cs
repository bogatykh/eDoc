using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib.Revocation;
using eDocLib.Revocation.Online;
using eDocLib.Revocation.Verify;
using eDocLib.Asic.Xades;

namespace eDocLib.Validation;

/// <summary>File-local helpers: merges national <see cref="TslQualificationMappingDefaults"/> with policy options.</summary>
file static class SignatureValidatorQualificationMapping
{
    /// <summary>Resolves the configured value.</summary>
    internal static TslQualificationMappingOptions? Resolve(SignatureTrustPolicy policy)
    {
        if (!policy.MergeTrustListQualificationUriDefaults)
        {
            return policy.TslQualificationMappingOptions;
        }

        return TslQualificationMappingOptions.Merge(
            TslQualificationMappingDefaults.LatvianNationalPublished,
            policy.TslQualificationMappingOptions)
            ?? TslQualificationMappingDefaults.LatvianNationalPublished;
    }
}

/// <summary>File-local helpers: derives revocation-report flags for edge-case PKIX paths.</summary>
file static class RevocationValidationReportExtras
{
    /// <summary>Returns whether online revocation fetch was skipped for a self-signed short chain.</summary>
    internal static bool OnlineFetchSkippedSelfSignedShortChain(
        SignatureTrustPolicy policy,
        bool? applicationOnlineRevocationValid,
        RevocationMaterialFetchResult? onlineFetched) =>
        policy.UsesApplicationControlledOnlineRevocation
        && applicationOnlineRevocationValid == true
        && onlineFetched is null;
}

/// <summary>File-local helpers: evaluates whether the signer certificate appears in a configured TSL index.</summary>
file static class SignatureValidatorTrustedList
{
    /// <summary>Carries evaluation data.</summary>
    internal readonly record struct Evaluation(
        bool Ok,
        string? Error,
        bool? Listed,
        IReadOnlyList<string>? ServiceTypeIds,
        string? ServiceStatus);

    /// <summary>Evaluates the configured state.</summary>
    internal static Evaluation Evaluate(SignatureTrustPolicy policy, X509Certificate2? signingCert)
    {
        if (policy.TrustedListServiceIndex is null)
            return new Evaluation(true, null, null, null, null);

        if (signingCert is null)
        {
            if (policy.RequireSigningCertificateListedInTrustedList)
            {
                return new Evaluation(
                    false,
                    "Signing certificate is required for trusted list qualification but was not found in the signature.",
                    null,
                    null,
                    null);
            }

            return new Evaluation(true, null, null, null, null);
        }

        if (policy.TrustedListServiceIndex.TryGetQualification(signingCert, out var q))
        {
            if (policy.TrustedListQualificationReferenceTimeUtc is { } refUtc)
            {
                q = TrustedListQualificationResolver.ResolveEffectiveQualification(q, refUtc);
            }

            return new Evaluation(true, null, true, q.ServiceTypeIdentifiers, q.ServiceStatusUri);
        }

        if (policy.RequireSigningCertificateListedInTrustedList)
        {
            return new Evaluation(
                false,
                "Signing certificate is not listed in the configured trusted service list.",
                false,
                null,
                null);
        }

        return new Evaluation(true, null, false, null, null);
    }
}

/// <summary>
/// XML-DSig reference digests + RSA (SHA-256 or SHA-384) or ECDSA over <c>SignedInfo</c>, optional <see cref="X509Chain"/> validation,
/// optional XAdES-T imprint and TSA token checks.
/// </summary>
internal static class SignatureValidator
{
    /// <summary>Validates current state.</summary>
    public static SignatureValidationResult Validate(
        XadesSignature signature,
        IReadOnlyDictionary<string, byte[]> payloadByRelativeUri,
        SignatureTrustPolicy? policy = null)
    {
        policy ??= SignatureTrustPolicy.CryptographyOnly;

        var embeddedOcspN = signature.UnsignedEncapsulatedOcspDer.Count;
        var embeddedCrlN = signature.UnsignedEncapsulatedCrlDer.Count;

        RevocationValidationReport Rev(
            bool pkixChainWasBuilt,
            bool? applicationOnlineChecked = null,
            bool? applicationOnlineValid = null,
            RevocationMaterialFetchResult? onlineFetched = null,
            bool? embeddedRevocationValid = null,
            IReadOnlyList<RevocationArtifactOutcome>? embeddedArtifactOutcomes = null,
            IReadOnlyList<RevocationArtifactOutcome>? onlineArtifactOutcomes = null) =>
            RevocationValidationReport.Create(
                policy,
                embeddedOcspN,
                embeddedCrlN,
                pkixChainWasBuilt,
                applicationOnlineChecked,
                applicationOnlineValid,
                onlineFetched,
                embeddedRevocationValid,
                RevocationValidationReportExtras.OnlineFetchSkippedSelfSignedShortChain(
                    policy,
                    applicationOnlineValid,
                    onlineFetched),
                embeddedArtifactOutcomes,
                onlineArtifactOutcomes);

        if (!DetachedSignatureVerifier.TryVerify(signature, payloadByRelativeUri, out var cryptoError, policy))
        {
            return new SignatureValidationResult
            {
                Success = false,
                Error = cryptoError,
                ReferencesAndSignatureValid = false,
                CertificateChainValid = policy.ValidateCertificateChain ? false : null,
                Revocation = Rev(false),
            };
        }

        if (!TryValidateClaimedSignerRoles(policy, signature, out var rolesError))
        {
            return new SignatureValidationResult
            {
                Success = false,
                Error = rolesError,
                ReferencesAndSignatureValid = true,
                CertificateChainValid = null,
                Revocation = Rev(false),
                SignerClaimedRolesConstraintOk = false,
            };
        }

        var owner = signature.GetSignatureOwnerDocument();
        var archDerList = XadesUnsignedEmbeddedValues.ReadEncapsulatedArchiveTimeStamps(owner);
        var archiveTimeStampCount = archDerList.Count;
        bool? archiveTimeStampsCmsValid = null;
        bool? archiveTimeStampsChainValid = null;
        bool? archiveTimeStampImprintsValid = null;
        var hasTs = SignatureTimestampVerifier.ContainsEmbeddedSignatureTimestamp(owner);

        bool? imprintValid = null;
        if (policy.TimestampImprintPolicy == SignatureTimestampImprintPolicy.RequireWhenPresent)
        {
            if (hasTs)
            {
                if (!SignatureTimestampVerifier.TryVerifySignatureTimeStampImprint(owner, out var tsError))
                {
                    return new SignatureValidationResult
                    {
                        Success = false,
                        Error = tsError,
                        ReferencesAndSignatureValid = true,
                        CertificateChainValid = null,
                        SignatureTimestampImprintValid = false,
                        Revocation = Rev(false),
                    };
                }

                imprintValid = true;
            }
        }

        bool? tsaCmsValid = null;
        bool? tsaChainValid = null;
        IReadOnlyList<CertificateChainDiagnostic>? tsaSignerChainDiag = null;

        SignatureValidationResult StampSlice() =>
            new()
            {
                SignatureTimestampImprintValid = imprintValid,
                TsaSignerCmsValid = tsaCmsValid,
                TsaSignerChainValid = tsaChainValid,
                TsaSignerCertificateChain = tsaSignerChainDiag,
                ArchiveTimeStampCount = archiveTimeStampCount,
                ArchiveTimeStampsCmsValid = archiveTimeStampsCmsValid,
                ArchiveTimeStampsChainValid = archiveTimeStampsChainValid,
                ArchiveTimeStampImprintsValid = archiveTimeStampImprintsValid,
                SignerClaimedRolesConstraintOk = policy.HasSignerClaimedRoleConstraints ? true : null,
            };

        var wantTsa = policy.ValidateTsaSigner || policy.ValidateTsaSignerChain;
        if (wantTsa && hasTs)
        {
            if (!SignatureTimestampVerifier.TryVerifyTsaTokenTrust(
                    owner,
                    policy,
                    out var tsaError,
                    out tsaCmsValid,
                    out tsaChainValid,
                    out tsaSignerChainDiag))
            {
                return StampSlice() with
                {
                    Success = false,
                    Error = tsaError,
                    ReferencesAndSignatureValid = true,
                    CertificateChainValid = null,
                    Revocation = Rev(false),
                };
            }
        }

        if (policy.ValidateArchiveTimeStampCms && archDerList.Count > 0)
        {
            foreach (var der in archDerList)
            {
                if (!SignatureTimestampVerifier.TryVerifyTimeStampTokenDer(
                        der,
                        policy,
                        verifyCms: true,
                        verifyChain: policy.ValidateArchiveTimeStampChain,
                        out var archiveErr,
                        out var aCms,
                        out var aChain,
                        out _))
                {
                    return StampSlice() with
                    {
                        Success = false,
                        Error = archiveErr,
                        ReferencesAndSignatureValid = true,
                        CertificateChainValid = null,
                        ArchiveTimeStampsCmsValid = aCms,
                        ArchiveTimeStampsChainValid = aChain,
                        Revocation = Rev(false),
                    };
                }
            }

            archiveTimeStampsCmsValid = true;
            archiveTimeStampsChainValid = policy.ValidateArchiveTimeStampChain ? true : null;
        }

        if (policy.ArchiveTimestampImprintPolicy == ArchiveTimestampImprintPolicy.RequireWhenPresent
            && archDerList.Count > 0)
        {
            if (!ArchiveTimestampImprintVerifier.TryVerifyAll(owner, archDerList, out var imprintErr))
            {
                return StampSlice() with
                {
                    Success = false,
                    Error = imprintErr,
                    ReferencesAndSignatureValid = true,
                    CertificateChainValid = null,
                    ArchiveTimeStampImprintsValid = false,
                    Revocation = Rev(false),
                };
            }

            archiveTimeStampImprintsValid = true;
        }

        var signingCert = signature.SigningCertificate as X509Certificate2;
        var tsl = SignatureValidatorTrustedList.Evaluate(policy, signingCert);
        if (!tsl.Ok)
        {
            return StampSlice() with
            {
                Success = false,
                Error = tsl.Error,
                ReferencesAndSignatureValid = true,
                CertificateChainValid = policy.ValidateCertificateChain ? false : null,
                SigningCertificateListedInTrustedList = tsl.Listed,
                TrustedListServiceTypeIdentifiers = tsl.ServiceTypeIds,
                TrustedListServiceStatus = tsl.ServiceStatus,
                TrustedListQualificationIndicators = tsl.Listed == true
                    ? TslQualificationMapper.Map(tsl.ServiceTypeIds, tsl.ServiceStatus, SignatureValidatorQualificationMapping.Resolve(policy))
                    : null,
                Revocation = Rev(false),
            };
        }

        var tslIndicators = tsl.Listed == true
            ? TslQualificationMapper.Map(tsl.ServiceTypeIds, tsl.ServiceStatus, SignatureValidatorQualificationMapping.Resolve(policy))
            : null;

        if (policy.RequireTrustedListServiceStatusGranted && policy.TrustedListServiceIndex is not null)
        {
            if (tsl.Listed != true || tslIndicators?.ServiceStatusIsGranted != true)
            {
                return StampSlice() with
                {
                    Success = false,
                    Error =
                        "Trusted list policy requires a granted TSL service status and a listed signing certificate.",
                    ReferencesAndSignatureValid = true,
                    CertificateChainValid = policy.ValidateCertificateChain ? false : null,
                    SigningCertificateListedInTrustedList = tsl.Listed,
                    TrustedListServiceTypeIdentifiers = tsl.ServiceTypeIds,
                    TrustedListServiceStatus = tsl.ServiceStatus,
                    TrustedListQualificationIndicators = tslIndicators,
                    Revocation = Rev(false),
                };
            }
        }

        if (!policy.ValidateCertificateChain)
        {
            return StampSlice() with
            {
                Success = true,
                ReferencesAndSignatureValid = true,
                CertificateChainValid = null,
                SigningCertificateListedInTrustedList = tsl.Listed,
                TrustedListServiceTypeIdentifiers = tsl.ServiceTypeIds,
                TrustedListServiceStatus = tsl.ServiceStatus,
                TrustedListQualificationIndicators = tslIndicators,
                Revocation = Rev(false),
            };
        }

        if (signingCert is null)
        {
            return StampSlice() with
            {
                Success = false,
                Error = "Cannot validate certificate chain: signing certificate missing.",
                ReferencesAndSignatureValid = true,
                CertificateChainValid = false,
                SigningCertificateListedInTrustedList = tsl.Listed,
                TrustedListServiceTypeIdentifiers = tsl.ServiceTypeIds,
                TrustedListServiceStatus = tsl.ServiceStatus,
                TrustedListQualificationIndicators = tslIndicators,
                Revocation = Rev(false),
            };
        }

        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        policy.ApplyRevocationMode(chain.ChainPolicy);

        if (policy.IncludeUnsignedCertificateValuesInSignerChain)
        {
            AddUnsignedCertificateValuesToExtraStore(signature, chain.ChainPolicy);
        }

        X509ChainBuildHelpers.ApplyExtraStore(chain.ChainPolicy, policy.ExtraChainCertificates);
        X509ChainBuildHelpers.ApplyTrustAnchors(chain.ChainPolicy, policy.CustomTrustAnchors);

        var chainOk = chain.Build(signingCert);
        var chainDiag = CertificateChainDiagnostics.FromChain(chain);
        if (!chainOk)
        {
            var status = X509ChainBuildHelpers.FormatChainStatus(chain);
            return StampSlice() with
            {
                Success = false,
                Error = "Certificate chain validation failed: " + status,
                ReferencesAndSignatureValid = true,
                CertificateChainValid = false,
                SigningCertificateListedInTrustedList = tsl.Listed,
                TrustedListServiceTypeIdentifiers = tsl.ServiceTypeIds,
                TrustedListServiceStatus = tsl.ServiceStatus,
                TrustedListQualificationIndicators = tslIndicators,
                SignerCertificateChain = chainDiag,
                Revocation = Rev(pkixChainWasBuilt: true),
            };
        }

        bool? appOnlineChecked = null;
        bool? appOnlineValid = null;
        RevocationMaterialFetchResult? onlineFetchedMaterial = null;
        IReadOnlyList<RevocationArtifactOutcome>? onlineArtifactOutcomes = null;
        if (policy.UsesApplicationControlledOnlineRevocation)
        {
            appOnlineChecked = true;
            if (!ApplicationOnlineRevocation.TryVerifyIfRequired(
                    policy,
                    signingCert,
                    chain,
                    out var onlineRevocationError,
                    out var onlineFetched,
                    out onlineArtifactOutcomes))
            {
                return StampSlice() with
                {
                    Success = false,
                    Error = onlineRevocationError,
                    ReferencesAndSignatureValid = true,
                    CertificateChainValid = true,
                    SigningCertificateListedInTrustedList = tsl.Listed,
                    TrustedListServiceTypeIdentifiers = tsl.ServiceTypeIds,
                    TrustedListServiceStatus = tsl.ServiceStatus,
                    TrustedListQualificationIndicators = tslIndicators,
                    SignerCertificateChain = chainDiag,
                    ApplicationOnlineRevocationChecked = true,
                    ApplicationOnlineRevocationValid = false,
                    Revocation = Rev(
                        true,
                        applicationOnlineChecked: true,
                        applicationOnlineValid: false,
                        onlineFetched: onlineFetched,
                        embeddedRevocationValid: null,
                        embeddedArtifactOutcomes: null,
                        onlineArtifactOutcomes: onlineArtifactOutcomes),
                };
            }

            appOnlineValid = true;
            onlineFetchedMaterial = onlineFetched;
        }

        IReadOnlyList<RevocationArtifactOutcome>? embeddedArtifactOutcomes = null;
        bool? unsignedRevocationValid = null;
        if (policy.VerifyUnsignedRevocationWhenPresent)
        {
            var ocsp = signature.UnsignedEncapsulatedOcspDer;
            var crls = signature.UnsignedEncapsulatedCrlDer;
            if (ocsp.Count > 0 || crls.Count > 0)
            {
                var path = X509ChainBuildHelpers.ToCertificatePath(chain);

                if (!EmbeddedRevocationVerifier.TryVerifyUnsignedArtifactsDetailed(
                        signingCert!,
                        ocsp,
                        crls,
                        path,
                        out var revErr,
                        out embeddedArtifactOutcomes,
                        policy.BuildEmbeddedOcspStrictOptions(),
                        policy.ExtraChainCertificates))
                {
                    return StampSlice() with
                    {
                        Success = false,
                        Error = revErr,
                        ReferencesAndSignatureValid = true,
                        CertificateChainValid = true,
                        SigningCertificateListedInTrustedList = tsl.Listed,
                        TrustedListServiceTypeIdentifiers = tsl.ServiceTypeIds,
                        TrustedListServiceStatus = tsl.ServiceStatus,
                        TrustedListQualificationIndicators = tslIndicators,
                        SignerCertificateChain = chainDiag,
                        UnsignedRevocationArtifactsValid = false,
                        ApplicationOnlineRevocationChecked = appOnlineChecked,
                        ApplicationOnlineRevocationValid = appOnlineValid,
                        Revocation = Rev(
                            true,
                            appOnlineChecked,
                            appOnlineValid,
                            onlineFetchedMaterial,
                            embeddedRevocationValid: false,
                            embeddedArtifactOutcomes,
                            onlineArtifactOutcomes),
                    };
                }

                unsignedRevocationValid = true;
            }
        }

        return StampSlice() with
        {
            Success = true,
            ReferencesAndSignatureValid = true,
            CertificateChainValid = true,
            SigningCertificateListedInTrustedList = tsl.Listed,
            TrustedListServiceTypeIdentifiers = tsl.ServiceTypeIds,
            TrustedListServiceStatus = tsl.ServiceStatus,
            TrustedListQualificationIndicators = tslIndicators,
            SignerCertificateChain = chainDiag,
            UnsignedRevocationArtifactsValid = unsignedRevocationValid,
            ApplicationOnlineRevocationChecked = appOnlineChecked,
            ApplicationOnlineRevocationValid = appOnlineValid,
            Revocation = Rev(
                true,
                appOnlineChecked,
                appOnlineValid,
                onlineFetchedMaterial,
                unsignedRevocationValid,
                embeddedArtifactOutcomes,
                onlineArtifactOutcomes),
        };
    }

    /// <summary>Adds unsigned certificate values to extra store.</summary>
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

    /// <summary>Attempts to validate claimed signer roles.</summary>
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

        var nonEmptyRoles = new List<string>();
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
