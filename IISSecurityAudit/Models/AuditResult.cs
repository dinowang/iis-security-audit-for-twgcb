namespace IISSecurityAudit.Models;

/// <summary>
/// 審核結果狀態
/// </summary>
public enum AuditStatus
{
    /// <summary>符合規範</summary>
    Pass,
    /// <summary>不符合規範</summary>
    Fail,
    /// <summary>需手動檢查</summary>
    Manual,
    /// <summary>不適用</summary>
    NotApplicable,
    /// <summary>檢查發生錯誤</summary>
    Error
}

/// <summary>
/// 單一檢查項目的審核結果
/// </summary>
public class AuditResult
{
    public TwgcbRule Rule { get; set; } = null!;
    public AuditStatus Status { get; set; }
    public string CurrentValue { get; set; } = string.Empty;
    public string ExpectedValue { get; set; } = string.Empty;
    public string Details { get; set; } = string.Empty;
    public string? ErrorMessage { get; set; }
    public DateTime CheckTime { get; set; } = DateTime.Now;
}
