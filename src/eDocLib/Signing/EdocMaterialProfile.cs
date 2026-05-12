namespace eDocLib.Signing;

/// <summary>Coarse material profile of a detached XAdES signature (informative, not a strict ETSI level).</summary>
public enum EdocMaterialProfile
{
    /// <summary>Could not classify embedded unsigned properties.</summary>
    Unknown = 0,

    /// <summary>XAdES-BES/B-T-style signature without embedded revocation archive blocks.</summary>
    Basic = 1,
    /// <summary>Embedded certificate and/or revocation material (XAdES-XL-style unsigned properties).</summary>
    LongTermMaterial = 2,
}
