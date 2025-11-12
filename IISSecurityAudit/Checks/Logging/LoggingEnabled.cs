using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.Logging;

/// <summary>
/// TWGCB-04-014-0040: 記錄檔設定
/// </summary>
public class LoggingEnabled : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0040";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "啟用記錄"
        };

        var sitesWithoutLogging = new List<string>();

        foreach (var site in serverManager.Sites)
        {
            if (site.LogFile.Enabled == false)
            {
                sitesWithoutLogging.Add(site.Name);
            }
        }

        if (sitesWithoutLogging.Count == 0)
        {
            result.Status = AuditStatus.Pass;
            result.CurrentValue = "所有站台已啟用記錄";
            result.Details = "檢查通過";
        }
        else
        {
            result.Status = AuditStatus.Fail;
            result.CurrentValue = $"{sitesWithoutLogging.Count} 個站台未啟用記錄";
            result.Details = $"未啟用記錄的站台:\n{string.Join("\n", sitesWithoutLogging)}";
        }

        return result;
    }
}
