using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.AspNetConfiguration;

/// <summary>
/// TWGCB-04-014-0016: 追蹤功能
/// </summary>
public class Tracing : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0016";

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
                var section = config.GetSection("system.web/trace");
                
                var enabled = section["enabled"];
                if (enabled != null && (bool)enabled)
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
            result.Details = "所有站台已停用追蹤功能";
        }
        else
        {
            result.Status = AuditStatus.Fail;
            result.CurrentValue = $"{violatingSites.Count} 個站台啟用追蹤功能";
            result.Details = $"啟用追蹤功能的站台:\n{string.Join("\n", violatingSites)}";
        }

        return result;
    }
}
