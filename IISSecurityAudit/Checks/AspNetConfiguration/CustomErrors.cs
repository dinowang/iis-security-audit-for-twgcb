using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.AspNetConfiguration;

/// <summary>
/// TWGCB-04-014-0015: 自訂錯誤訊息顯示模式
/// </summary>
public class CustomErrors : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0015";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "On 或 RemoteOnly"
        };

        var violatingSites = new List<string>();

        foreach (var site in serverManager.Sites)
        {
            try
            {
                var config = serverManager.GetWebConfiguration(site.Name);
                var section = config.GetSection("system.web/customErrors");
                
                var mode = section["mode"]?.ToString();
                if (mode != "On" && mode != "RemoteOnly")
                {
                    violatingSites.Add($"{site.Name} ({mode ?? "Off"})");
                }
            }
            catch { }
        }

        if (violatingSites.Count == 0)
        {
            result.Status = AuditStatus.Pass;
            result.CurrentValue = "On 或 RemoteOnly";
            result.Details = "所有站台的自訂錯誤模式設定正確";
        }
        else
        {
            result.Status = AuditStatus.Fail;
            result.CurrentValue = $"{violatingSites.Count} 個站台設定不正確";
            result.Details = $"設定不正確的站台:\n{string.Join("\n", violatingSites)}";
        }

        return result;
    }
}
