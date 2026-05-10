namespace eDocLib.Validation.Reporting;

/// <summary>Heuristic signature qualification derived from validation outcome and trust-list hints.</summary>
public enum SignatureQualification
{
    /// <summary>Qualified electronic signature.</summary>
    QESig,

    /// <summary>Qualified electronic seal.</summary>
    QESeal,

    /// <summary>Advanced electronic signature.</summary>
    ADESig,

    /// <summary>Advanced electronic seal.</summary>
    ADESeal,

    /// <summary>Signature qualification could not be determined.</summary>
    Unknown,
}
