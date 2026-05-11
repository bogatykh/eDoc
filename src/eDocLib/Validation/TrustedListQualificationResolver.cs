namespace eDocLib.Validation;

/// <summary>
/// Chooses <see cref="TrustedListQualification.ServiceTypeIdentifiers"/> and <see cref="TrustedListQualification.ServiceStatusUri"/>
/// for a UTC reference instant using dated <see cref="TrustedListQualification.ServiceHistory"/> rows (ETSI TS 119 612).
/// </summary>
/// <remarks>
/// Rows with a parseable <see cref="TrustedListServiceHistorySnapshot.StatusStartingTime"/> partition the timeline into half-open
/// segments <c>[tᵢ, tᵢ₊₁)</c>. The segment after the last dated row follows published <c>ServiceInformation</c> on the
/// qualification object (current list row). When the validation reference instant falls before the first dated segment start,
/// <see cref="ResolveEffectiveQualification"/> returns the input qualification unchanged (caller-defined interpretation — typically current published state).
/// </remarks>
internal static class TrustedListQualificationResolver
{
    /// <summary>
    /// Returns a qualification view whose service types/status reflect <paramref name="referenceUtc"/> when history segments apply.
    /// </summary>
    public static TrustedListQualification ResolveEffectiveQualification(
        TrustedListQualification qualification,
        DateTimeOffset referenceUtc)
    {
        ArgumentNullException.ThrowIfNull(qualification);

        var hist = qualification.ServiceHistory;
        if (hist is null || hist.Count == 0)
        {
            return qualification;
        }

        var timed = hist
            .Where(h => h.StatusStartingTime.HasValue)
            .OrderBy(h => h.StatusStartingTime!.Value)
            .ToList();

        if (timed.Count == 0)
        {
            return qualification;
        }

        for (var i = 0; i < timed.Count; i++)
        {
            var start = timed[i].StatusStartingTime!.Value;
            if (referenceUtc < start)
            {
                continue;
            }

            if (i == timed.Count - 1)
            {
                return qualification;
            }

            var nextStart = timed[i + 1].StatusStartingTime!.Value;
            if (referenceUtc < nextStart)
            {
                return WithServiceFieldsFromHistorySnapshot(qualification, timed[i]);
            }
        }

        return qualification;
    }

    private static TrustedListQualification WithServiceFieldsFromHistorySnapshot(
        TrustedListQualification original,
        TrustedListServiceHistorySnapshot row)
    {
        return new TrustedListQualification
        {
            ServiceTypeIdentifiers = row.ServiceTypeIdentifiers,
            ServiceStatusUri = row.ServiceStatusUri,
            ServiceHistory = original.ServiceHistory,
        };
    }
}
