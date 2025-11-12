using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.Logging;

/// <summary>
/// TWGCB-04-014-0038: 記錄檔格式
/// </summary>
public class LogFileFormat : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0038";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "W3C"
        };

        var sitesWithWrongFormat = new List<string>();

        foreach (var site in serverManager.Sites)
        {
            var logFormat = site.LogFile.LogFormat.ToString();
            if (logFormat != "W3c")
            {
                sitesWithWrongFormat.Add($"{site.Name} - {logFormat}");
            }
        }

        if (sitesWithWrongFormat.Count == 0)
        {
            result.Status = AuditStatus.Pass;
            result.CurrentValue = "W3C";
            result.Details = "所有站台皆使用 W3C 記錄格式";
        }
        else
        {
            result.Status = AuditStatus.Fail;
            result.CurrentValue = $"{sitesWithWrongFormat.Count} 個站台使用其他格式";
            result.Details = $"未使用 W3C 格式的站台:\n{string.Join("\n", sitesWithWrongFormat)}";
        }

        return result;
    }
}
