using eDocLib.Validation;

namespace eDocLib;

/// <summary>
/// Document that can be validated with <see cref="SignatureTrustPolicy"/>.
/// </summary>
public interface IValidatableDocument
{
    /// <summary>
    /// Runs the same checks as <see cref="EdocValidation.ValidateSignatures"/>.
    /// The returned <see cref="EdocReadValidationResult"/> also implements <see cref="IEdocContainerValidationResult"/> for aggregate-only consumers.
    /// </summary>
    EdocReadValidationResult Validate(SignatureTrustPolicy? trustPolicy = null);
}
