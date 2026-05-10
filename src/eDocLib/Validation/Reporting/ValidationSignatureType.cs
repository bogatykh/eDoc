namespace eDocLib.Validation.Reporting;

/// <summary>Container or format kind for the signature (e.g. ASiC-E XML vs PDF).</summary>
public enum ValidationSignatureType
{
    /// <summary>eDoc version 1 container signature.</summary>
    EdocV1,

    /// <summary>eDoc version 2 container signature.</summary>
    EdocV2,

    /// <summary>PDF signature using Adobe PKCS#7 detached encoding.</summary>
    PdfAdobePkcs7Detached,

    /// <summary>PDF signature using ETSI CAdES detached encoding.</summary>
    PdfEtsiCadesDetached,

    /// <summary>Signature type could not be determined.</summary>
    UnknownType,
}
