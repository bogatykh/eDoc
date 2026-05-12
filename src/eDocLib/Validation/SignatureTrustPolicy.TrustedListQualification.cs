namespace eDocLib.Validation;

public sealed partial class SignatureTrustPolicy
{
    /// <summary>
    /// Optional index of <c>TSPService/ServiceInformation</c> entries (e.g. from parsing a trusted list XML into a
    /// <see cref="TrustedListServiceIndex"/>). When set, validation records qualification metadata
    /// and can require the signing certificate to appear in the list.
    /// </summary>
    public TrustedListServiceIndex? TrustedListServiceIndex { get; init; }

    /// <summary>
    /// When set together with <see cref="TrustedListServiceIndex"/>, TSL service type and status for qualification mapping use the
    /// <see cref="TrustedListQualification.ServiceHistory"/> segment active at this UTC instant (ETSI TS 119 612).
    /// When <c>null</c>, only current <c>ServiceInformation</c> on the index entry applies.
    /// </summary>
    public DateTimeOffset? TrustedListQualificationReferenceTimeUtc { get; init; }

    /// <summary>Optional extra TSL status / service-type URIs merged into qualification mapping (national lists).</summary>
    public TslQualificationMappingOptions? TslQualificationMappingOptions { get; init; }

    /// <summary>
    /// When <c>true</c> (default), merges built-in national URI additions for Latvia into
    /// <see cref="TslQualificationMappingOptions"/> before qualification mapping (additive URI unions).
    /// Set <c>false</c> to use only explicit options and the core ETSI URI sets from mapping options.
    /// </summary>
    /// <remarks>
    /// This flag exists for historical reasons: the Latvian national TSL publishes ETSI <c>accredited</c>
    /// alongside <c>granted</c> / <c>recognisedatnationallevel</c>, and early integrators relied on the
    /// library merging that mapping silently. Hosts deploying to other jurisdictions should set this to
    /// <c>false</c> and pass an explicit <see cref="TslQualificationMappingOptions"/> with the URI sets
    /// applicable to their territory; rely on this flag only for Latvian deployments.
    /// </remarks>
    public bool MergeTrustListQualificationUriDefaults { get; init; } = true;

    /// <summary>
    /// Resolves the effective <see cref="TslQualificationMappingOptions"/> for this policy: merges the
    /// optional national defaults gated by <see cref="MergeTrustListQualificationUriDefaults"/> with any
    /// caller-supplied <see cref="TslQualificationMappingOptions"/>. Returns <c>null</c> when there is
    /// nothing to merge (no defaults requested and no caller options).
    /// </summary>
    /// <remarks>
    /// The validator calls this rather than reaching into territory-specific defaults from inside the
    /// generic verification engine, so the host-visible policy is the single point that decides whether
    /// a national mapping bundle is merged in.
    /// </remarks>
    internal TslQualificationMappingOptions? ResolveQualificationMappingOptions()
    {
        if (!MergeTrustListQualificationUriDefaults)
        {
            return TslQualificationMappingOptions;
        }

        return TslQualificationMappingOptions.Merge(
            TslQualificationMappingDefaults.LatvianNationalPublished,
            TslQualificationMappingOptions)
            ?? TslQualificationMappingDefaults.LatvianNationalPublished;
    }

    /// <summary>
    /// When <c>true</c> and <see cref="TrustedListServiceIndex"/> is non-null, validation fails if the signing certificate
    /// is missing or not listed under any <c>ServiceInformation</c> block.
    /// </summary>
    public bool RequireSigningCertificateListedInTrustedList { get; init; }

    /// <summary>
    /// When <c>true</c> and <see cref="TrustedListServiceIndex"/> is non-null, the signer must be listed and the TSL
    /// <c>ServiceStatus</c> must be one of the granted-like URIs recognised by the configured qualification mapping.
    /// </summary>
    public bool RequireTrustedListServiceStatusGranted { get; init; }
}
