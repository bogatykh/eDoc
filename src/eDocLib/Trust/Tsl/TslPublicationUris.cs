namespace eDocLib.Trust.Tsl;

/// <summary>
/// Public trusted-list publication URIs: EU LOTL (Commission) and, where listed, national scheme URLs.
/// </summary>
internal static class TslPublicationUris
{
    /// <summary>Defines the eu list of trusted lists value.</summary>
    public const string EuListOfTrustedLists = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";

    /// <summary>EU third-country AdES list of trusted lists.</summary>
    public const string EuThirdCountryAdesListOfTrustedLists = "https://ec.europa.eu/tools/lotl/mra/ades-lotl.xml";

    /// <summary>Defines the eu lotl territory key value.</summary>
    public const string EuLotlTerritoryKey = "EU";

    /// <summary>Territory key for <see cref="EuThirdCountryAdesListOfTrustedLists"/>.</summary>
    public const string EuTcAdesLotlTerritoryKey = "EU-TC";

    /// <summary>ISO 3166-1 alpha-2 territory key for Latvia.</summary>
    public const string LatviaTerritoryKey = "LV";

    /// <summary>
    /// Latvia national TSL XML as published for the EU LOTL pointer (<c>trustlist.gov.lv</c>).
    /// Prefer resolving via <see cref="EuLotlPointerLocator"/> if you need the URL exactly as in the current LOTL snapshot.
    /// </summary>
    public const string LatviaNationalTrustedList = "https://trustlist.gov.lv/tsl/latvian-tsl.xml";
}
