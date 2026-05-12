using eDocLib.Validation.Reporting;

namespace eDocLib.Validation;

/// <summary>Builds hierarchical validation reports from container-level validation results.</summary>
public static class EdocContainerValidationReportExtensions
{
    /// <inheritdoc cref="BuildValidationReport(EdocReadValidationResult, SignatureTrustPolicy, ValidationReportOptions?)"/>
    public static DocumentValidationReport BuildValidationReport(this EdocReadValidationResult result, SignatureTrustPolicy policy) =>
        BuildValidationReport(result, policy, reportOptions: null);

    /// <summary>Builds a validation report for the opened container and each signature row. Use <see cref="ValidationReportOptions"/> for reference time and optional tree/summary strings (<see cref="ValidationReportOptions.ReportLocalizer"/>).</summary>
    public static DocumentValidationReport BuildValidationReport(
        this EdocReadValidationResult result,
        SignatureTrustPolicy policy,
        ValidationReportOptions? reportOptions)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(policy);
        return ValidationReportFactory.CreateDocumentReport(result, policy, reportOptions);
    }

    /// <inheritdoc cref="BuildValidationReport(IEdocContainerValidationResult, SignatureTrustPolicy, ValidationReportOptions?)"/>
    public static DocumentValidationReport BuildValidationReport(this IEdocContainerValidationResult result, SignatureTrustPolicy policy) =>
        BuildValidationReport(result, policy, reportOptions: null);

    /// <summary>Builds a validation report when the outcome is exposed as <see cref="IEdocContainerValidationResult"/> (see <see cref="ValidationReportOptions"/>).</summary>
    public static DocumentValidationReport BuildValidationReport(
        this IEdocContainerValidationResult result,
        SignatureTrustPolicy policy,
        ValidationReportOptions? reportOptions)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(policy);
        return ValidationReportFactory.CreateDocumentReport(result, policy, reportOptions);
    }
}
