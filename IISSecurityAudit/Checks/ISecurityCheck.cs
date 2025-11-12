using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks;

/// <summary>
/// 檢查項目的基礎介面
/// </summary>
public interface ISecurityCheck
{
    /// <summary>
    /// 執行安全檢查
    /// </summary>
    /// <param name="serverManager">IIS ServerManager 實例</param>
    /// <param name="rule">要檢查的規則</param>
    /// <returns>審核結果</returns>
    AuditResult Execute(ServerManager serverManager, TwgcbRule rule);
    
    /// <summary>
    /// 取得此檢查支援的規則ID
    /// </summary>
    string SupportedRuleId { get; }
}

/// <summary>
/// 基礎安全檢查抽象類別，提供例外處理
/// </summary>
public abstract class SecurityCheckBase : ISecurityCheck
{
    public abstract string SupportedRuleId { get; }
    
    public AuditResult Execute(ServerManager serverManager, TwgcbRule rule)
    {
        try
        {
            return ExecuteCheck(serverManager, rule);
        }
        catch (Exception ex)
        {
            return new AuditResult
            {
                Rule = rule,
                Status = AuditStatus.Error,
                ErrorMessage = $"檢查發生例外: {ex.Message}",
                Details = ex.ToString()
            };
        }
    }
    
    /// <summary>
    /// 實際執行檢查的方法，由子類別實作
    /// </summary>
    protected abstract AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule);
}
