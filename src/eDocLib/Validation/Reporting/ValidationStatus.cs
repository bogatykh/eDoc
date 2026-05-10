namespace eDocLib.Validation.Reporting;

/// <summary>Validation outcome for a single tree node. <see cref="Indeterminate"/> is used when the result is inconclusive under the active policy.</summary>
public enum ValidationStatus
{
    /// <summary>Validation passed.</summary>
    Passed,

    /// <summary>Validation failed.</summary>
    Failed,

    /// <summary>Validation was not checked.</summary>
    Unchecked,

    /// <summary>Neither clearly passed nor failed under current policy.</summary>
    Indeterminate,
}
