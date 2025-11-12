using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.AspNetConfiguration;

/// <summary>
/// TWGCB-04-014-0014: 偵錯功能
/// </summary>
public class DebugMode : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0014";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "False"
        };

        var violatingSites = new List<string>();

        foreach (var site in serverManager.Sites)
        {
            try
            {
                var config = serverManager.GetWebConfiguration(site.Name);
                var section = config.GetSection("system.web/compilation");
                
                var debug = section["debug"];
                if (debug != null && (bool)debug)
                {
                    violatingSites.Add(site.Name);
                }
            }
            catch { }
        }

        if (violatingSites.Count == 0)
        {
            result.Status = AuditStatus.Pass;
            result.CurrentValue = "False";
            result.Details = "所有站台已停用偵錯模式";
        }
        else
        {
            result.Status = AuditStatus.Fail;
            result.CurrentValue = $"{violatingSites.Count} 個站台啟用偵錯模式";
            result.Details = $"啟用偵錯模式的站台:\n{string.Join("\n", violatingSites)}";
        }

        return result;
    }
}
