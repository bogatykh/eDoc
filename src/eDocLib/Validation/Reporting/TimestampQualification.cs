namespace eDocLib.Validation.Reporting;

/// <summary>Heuristic time-stamp service qualification for reporting.</summary>
public enum TimestampQualification
{
    /// <summary>Qualified timestamp service authority.</summary>
    QTsa,

    /// <summary>Timestamp service authority.</summary>
    Tsa,

    /// <summary>Timestamp qualification could not be determined.</summary>
    Unknown,
}
