using System.Text;
using eDocLib.Validation;

namespace eDocLib.Validation.Reporting;

/// <summary>Plain-text rendering of <see cref="DocumentValidationReport"/>.</summary>
internal static class ValidationReportTextFormatter
{
    /// <summary>Formats document.</summary>
    public static string FormatDocument(DocumentValidationReport report, IValidationReportLocalizer? localizer = null)
    {
        ArgumentNullException.ThrowIfNull(report);
        localizer ??= new DefaultValidationReportLocalizer();

        var sb = new StringBuilder();
        sb.AppendLine(
            report.AllSignaturesValid
                ? "Document: all signatures valid."
                : "Document: one or more signatures invalid.");
        sb.AppendLine();
        FormatNode(sb, report.Root, localizer, depth: 0);

        sb.AppendLine();
        sb.AppendLine("--- Per-signature summary ---");
        foreach (var s in report.Signatures)
        {
            sb.AppendLine();
            sb.AppendLine(FormatSignatureSummary(s, localizer));
        }

        return sb.ToString();
    }

    /// <summary>Formats signature summary.</summary>
    public static string FormatSignatureSummary(SignatureValidationReport report, IValidationReportLocalizer? localizer)
    {
        ArgumentNullException.ThrowIfNull(report);
        localizer ??= new DefaultValidationReportLocalizer();

        var sb = new StringBuilder();
        sb.AppendLine($"Signature #{report.Ordinal} ({report.Tree.Id ?? "(no id)"})");
        sb.AppendLine($"Indication: {localizer.Indication(report.Indication)}");
        var hint = localizer.LegalBasisHint(report.Indication);
        if (!string.IsNullOrEmpty(hint))
        {
            sb.AppendLine($"Note: {hint}");
        }

        sb.AppendLine($"Format: {localizer.DescribeValidationSignatureType(report.ValidationSignatureType)}");
        sb.AppendLine($"Profile: {localizer.DescribeSignatureProfile(report.SignatureProfile)}");
        sb.AppendLine($"Signature qualification: {localizer.DescribeSignatureQualification(report.SignatureQualification)}");
        sb.AppendLine($"Signer certificate qualification: {localizer.DescribeCertificateQualification(report.SignerCertificateQualification)}");
        sb.AppendLine($"Timestamp qualification: {localizer.DescribeTimestampQualification(report.TimestampQualification)}");
        return sb.ToString();
    }

    /// <summary>Formats node.</summary>
    private static void FormatNode(StringBuilder sb, ValidationResultNode node, IValidationReportLocalizer localizer, int depth)
    {
        var pad = new string(' ', depth * 2);
        var line = $"{pad}- {localizer.ValidationTypeCaption(node.Type)}: {localizer.DescribeValidationStatus(node.Status)}";
        if (!string.IsNullOrEmpty(node.Id))
        {
            line += $" [id={node.Id}]";
        }

        if (!string.IsNullOrEmpty(node.Description))
        {
            line += $" — {node.Description}";
        }

        sb.AppendLine(line);
        foreach (var r in node.Reasons)
        {
            sb.AppendLine($"{pad}    ! {r}");
        }

        foreach (var c in node.Children)
        {
            FormatNode(sb, c, localizer, depth + 1);
        }
    }
}
