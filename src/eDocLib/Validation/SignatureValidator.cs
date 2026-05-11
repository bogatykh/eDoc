using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using eDocLib.Revocation;
using eDocLib.Revocation.Online;
using eDocLib.Revocation.Verify;
using eDocLib.Asic.Xades;

namespace eDocLib.Validation;

/// <summary>
/// XML-DSig reference digests + RSA (SHA-256 or SHA-384) or ECDSA over <c>SignedInfo</c>, optional <see cref="X509Chain"/> validation,
/// optional XAdES-T imprint and TSA token checks.
/// </summary>
internal static partial class SignatureValidator
{
    public static Task<SignatureValidationResult> ValidateAsync(
        XadesSignature signature,
        IReadOnlyDictionary<string, byte[]> payloadByRelativeUri,
        SignatureTrustPolicy? policy = null,
        CancellationToken cancellationToken = default) =>
        ValidateAsync(
            signature,
            new InMemoryPayloadSource(payloadByRelativeUri ?? throw new ArgumentNullException(nameof(payloadByRelativeUri))),
            policy,
            cancellationToken);

    internal static async Task<SignatureValidationResult> ValidateAsync(
        XadesSignature signature,
        IValidationPayloadSource payloadSource,
        SignatureTrustPolicy? policy = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(payloadSource);
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

        if (!DetachedSignatureVerifier.TryVerify(signature, payloadSource, out var cryptoError, policy))
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
            var tsaRes = await SignatureTimestampVerifier.TryVerifyTsaTokenTrustAsync(owner, policy, cancellationToken)
                .ConfigureAwait(false);
            if (!tsaRes.Ok)
            {
                return StampSlice() with
                {
                    Success = false,
                    Error = tsaRes.Error,
                    ReferencesAndSignatureValid = true,
                    CertificateChainValid = null,
                    TsaSignerCmsValid = tsaRes.CmsValid,
                    TsaSignerChainValid = tsaRes.ChainValid,
                    TsaSignerCertificateChain = tsaRes.CertificateChain,
                    Revocation = Rev(false),
                };
            }

            tsaCmsValid = tsaRes.CmsValid;
            tsaChainValid = tsaRes.ChainValid;
            tsaSignerChainDiag = tsaRes.CertificateChain;
        }

        if (policy.ValidateArchiveTimeStampCms && archDerList.Count > 0)
        {
            foreach (var der in archDerList)
            {
                var archiveRes = await SignatureTimestampVerifier.TryVerifyTimeStampTokenDerAsync(
                        der,
                        policy,
                        verifyCms: true,
                        verifyChain: policy.ValidateArchiveTimeStampChain,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (!archiveRes.Ok)
                {
                    return StampSlice() with
                    {
                        Success = false,
                        Error = archiveRes.Error,
                        ReferencesAndSignatureValid = true,
                        CertificateChainValid = null,
                        ArchiveTimeStampsCmsValid = archiveRes.CmsValid,
                        ArchiveTimeStampsChainValid = archiveRes.ChainValid,
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
                    ? TslQualificationMapper.Map(tsl.ServiceTypeIds, tsl.ServiceStatus, policy.ResolveQualificationMappingOptions())
                    : null,
                Revocation = Rev(false),
            };
        }

        var tslIndicators = tsl.Listed == true
            ? TslQualificationMapper.Map(tsl.ServiceTypeIds, tsl.ServiceStatus, policy.ResolveQualificationMappingOptions())
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

        using var chain = policy.CreateX509Chain();

        if (policy.IncludeUnsignedCertificateValuesInSignerChain)
        {
            AddUnsignedCertificateValuesToExtraStore(signature, chain.ChainPolicy);
        }

        policy.ApplySignerChainStores(chain.ChainPolicy);

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
            var onlineOutcome = await ApplicationOnlineRevocation.TryVerifyIfRequiredAsync(
                    policy,
                    signingCert,
                    chain,
                    materialFetcher: null,
                    cancellationToken)
                .ConfigureAwait(false);
            if (!onlineOutcome.Ok)
            {
                return StampSlice() with
                {
                    Success = false,
                    Error = onlineOutcome.Error,
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
                        onlineFetched: onlineOutcome.Fetched,
                        embeddedRevocationValid: null,
                        embeddedArtifactOutcomes: null,
                        onlineArtifactOutcomes: onlineOutcome.Artifacts),
                };
            }

            appOnlineValid = true;
            onlineFetchedMaterial = onlineOutcome.Fetched;
            onlineArtifactOutcomes = onlineOutcome.Artifacts;
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
}
