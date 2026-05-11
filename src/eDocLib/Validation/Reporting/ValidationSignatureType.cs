namespace eDocLib.Validation.Reporting;

/// <summary>Container or format kind for the signature (ASiC-E / XML eDoc).</summary>
public enum ValidationSignatureType
{
    /// <summary>eDoc version 2 container signature (ASiC-E / XAdES).</summary>
    EdocV2,

    /// <summary>Signature type could not be determined.</summary>
    UnknownType,
}
