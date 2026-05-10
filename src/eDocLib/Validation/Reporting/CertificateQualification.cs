namespace eDocLib.Validation.Reporting;

/// <summary>Heuristic signer certificate qualification for reporting.</summary>
public enum CertificateQualification
{
    /// <summary>Electronic-signature certificate.</summary>
    ESig,

    /// <summary>Electronic-seal certificate.</summary>
    ESeal,

    /// <summary>Qualified electronic-signature certificate.</summary>
    QcESig,

    /// <summary>Qualified electronic-seal certificate.</summary>
    QcESeal,

    /// <summary>Qualified electronic-signature certificate with a qualified creation device indication.</summary>
    QcQscdESig,

    /// <summary>Qualified electronic-seal certificate with a qualified creation device indication.</summary>
    QcQscdESeal,

    /// <summary>Qualified certificate with a creation device indication but unknown signature or seal role.</summary>
    QcQscdUnknown,

    /// <summary>Qualified certificate with unknown signature or seal role.</summary>
    QcUnknown,

    /// <summary>Certificate qualification could not be determined.</summary>
    Unknown,
}
