using System.Threading;
using System.Threading.Tasks;

namespace eDocLib.Validation;

/// <summary>
/// Document that can be validated with <see cref="SignatureTrustPolicy"/>.
/// </summary>
public interface IValidatableDocument
{
    /// <summary>
    /// Runs the same checks as <see cref="EdocContainerSignatureValidator.ValidateSignaturesAsync"/>.
    /// The returned <see cref="EdocReadValidationResult"/> also implements <see cref="IEdocContainerValidationResult"/> for aggregate-only consumers.
    /// </summary>
    Task<EdocReadValidationResult> ValidateAsync(
        SignatureTrustPolicy? trustPolicy = null,
        CancellationToken cancellationToken = default);
}
