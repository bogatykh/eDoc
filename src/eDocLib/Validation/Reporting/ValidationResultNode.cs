namespace eDocLib.Validation.Reporting;

/// <summary>Hierarchical validation report node (type, status, optional reasons, child nodes).</summary>
/// <param name="Type">Semantic role of the node.</param>
/// <param name="Status">Validation status for this node.</param>
/// <param name="Id">Optional stable identifier for the node.</param>
/// <param name="Description">Optional human-readable description.</param>
/// <param name="Reasons">Reasons attached to this node.</param>
/// <param name="Children">Child validation nodes.</param>
public sealed record ValidationResultNode(
    ValidationType Type,
    ValidationStatus Status,
    string? Id,
    string? Description,
    IReadOnlyList<string> Reasons,
    IReadOnlyList<ValidationResultNode> Children)
{
    /// <summary>Creates a leaf validation node.</summary>
    public static ValidationResultNode Leaf(
        ValidationType type,
        ValidationStatus status,
        string? id = null,
        string? description = null,
        IReadOnlyList<string>? reasons = null) =>
        new(type, status, id, description, reasons ?? Array.Empty<string>(), Array.Empty<ValidationResultNode>());

    /// <summary>Creates a branch validation node.</summary>
    public static ValidationResultNode Branch(
        ValidationType type,
        ValidationStatus status,
        IReadOnlyList<ValidationResultNode> children,
        string? id = null,
        string? description = null,
        IReadOnlyList<string>? reasons = null) =>
        new(type, status, id, description, reasons ?? Array.Empty<string>(), children);
}
