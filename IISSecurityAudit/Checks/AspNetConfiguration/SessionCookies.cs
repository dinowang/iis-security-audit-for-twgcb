using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.AspNetConfiguration;

/// <summary>
/// TWGCB-04-014-0030: Session State Cookie 設定
/// </summary>
public class SessionCookies : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0030";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "UseUri"
        };

        var violatingSites = new List<string>();

        foreach (var site in serverManager.Sites)
        {
            try
            {
                var config = serverManager.GetWebConfiguration(site.Name);
                var section = config.GetSection("system.web/sessionState");
                
                var cookieless = section["cookieless"]?.ToString();
                if (cookieless != "UseUri" && cookieless != "UseCookies")
                {
                    violatingSites.Add($"{site.Name} ({cookieless ?? "未設定"})");
                }
            }
            catch { }
        }

        if (violatingSites.Count == 0)
        {
            result.Status = AuditStatus.Pass;
            result.CurrentValue = "設定正確";
            result.Details = "所有站台的 Session Cookie 設定正確";
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
