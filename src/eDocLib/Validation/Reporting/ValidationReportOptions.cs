namespace eDocLib.Validation.Reporting;

/// <summary>Optional settings when building a structured validation report (tree shape and time references).</summary>
public sealed record ValidationReportOptions
{
    /// <summary>
    /// When set, certificate NotBefore/NotAfter nodes in the PKIX branch are evaluated against this instant instead of
    /// <see cref="DateTimeOffset.UtcNow"/>. Useful for reproducible reports and “validate as at signing time” scenarios.
    /// </summary>
    public DateTimeOffset? ReferenceTimeUtc { get; init; }
}
