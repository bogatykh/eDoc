namespace eDocLib.Validation.Reporting;

/// <summary>
/// Document-level report: aggregate validity, root <see cref="ValidationResultNode"/> tree, and per-signature sections.
/// Use this type as the canonical validation snapshot for UI or HTTP responses; any extra wire DTOs belong in the host, projected from this model.
/// </summary>
public sealed record DocumentValidationReport(
    bool AllSignaturesValid,
    ValidationResultNode Root,
    IReadOnlyList<SignatureValidationReport> Signatures)
{
    /// <summary>Plain-text rendering for logging or console; optional custom <see cref="IValidationReportLocalizer"/>.</summary>
    public string ToPlainText(IValidationReportLocalizer? localizer = null) =>
        ValidationReportTextFormatter.FormatDocument(this, localizer);
}
