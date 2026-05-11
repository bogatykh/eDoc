using System.Collections.Generic;

namespace eDocLib.Validation.Reporting;

internal static partial class ValidationReportFactory
{
    private static ValidationStatus Tri(bool? value) =>
        value switch
        {
            true => ValidationStatus.Passed,
            false => ValidationStatus.Failed,
            _ => ValidationStatus.Unchecked,
        };

    private static string ChainPositionLabel(int index, int chainLength)
    {
        if (chainLength <= 0)
        {
            return "Certificate";
        }

        if (index == 0)
        {
            return "End entity";
        }

        if (index == chainLength - 1)
        {
            return "Trust anchor";
        }

        return "Intermediate";
    }

    private static ValidationStatus AggregateChildren(IReadOnlyList<ValidationResultNode> nodes)
    {
        var anyFailed = false;
        var anyIndeterminate = false;
        var anyPassed = false;
        for (var i = 0; i < nodes.Count; i++)
        {
            switch (nodes[i].Status)
            {
                case ValidationStatus.Failed:
                    anyFailed = true;
                    break;
                case ValidationStatus.Indeterminate:
                    anyIndeterminate = true;
                    break;
                case ValidationStatus.Passed:
                    anyPassed = true;
                    break;
            }
        }

        if (anyFailed)
        {
            return ValidationStatus.Failed;
        }

        if (anyIndeterminate)
        {
            return ValidationStatus.Indeterminate;
        }

        if (anyPassed)
        {
            return ValidationStatus.Passed;
        }

        return ValidationStatus.Unchecked;
    }

    private static IReadOnlyList<string> SingleReason(string? error) =>
        string.IsNullOrWhiteSpace(error) ? Array.Empty<string>() : new[] { error.Trim() };

    /// <summary>Empty when <paramref name="referencesAndSignatureValid"/>; otherwise the primary error for crypto layers (method, refs, value, etc.).</summary>
    private static IReadOnlyList<string> CryptoValidationReasons(bool referencesAndSignatureValid, string? error) =>
        referencesAndSignatureValid ? Array.Empty<string>() : SingleReason(error);

    /// <summary><see cref="ValidationStatus.Passed"/> when digest + XML-DSig signature succeeded; otherwise <see cref="ValidationStatus.Failed"/>.</summary>
    private static ValidationStatus CryptoLayerStatus(bool referencesAndSignatureValid) =>
        referencesAndSignatureValid ? ValidationStatus.Passed : ValidationStatus.Failed;
}
