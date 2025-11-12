namespace IISSecurityAudit.Models;

/// <summary>
/// TWGCB-04-014 政府組態基準規則定義
/// </summary>
public class TwgcbRule
{
    public int ItemNumber { get; set; }
    public string Id { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Location { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
}
