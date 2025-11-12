using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks;

/// <summary>
/// 通用手動檢查處理器 - 用於需要人工判斷的檢查項目
/// </summary>
public class ManualCheck : SecurityCheckBase
{
    private readonly string _ruleId;

    public ManualCheck(string ruleId)
    {
        _ruleId = ruleId;
    }

    public override string SupportedRuleId => _ruleId;

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        return new AuditResult
        {
            Rule = rule,
            Status = AuditStatus.Manual,
            ExpectedValue = rule.Value,
            CurrentValue = "需手動檢查",
            Details = $"請依據以下路徑手動檢查:\n{rule.Path}\n\n設定位置: {rule.Location}\n期望值: {rule.Value}"
        };
    }
}
