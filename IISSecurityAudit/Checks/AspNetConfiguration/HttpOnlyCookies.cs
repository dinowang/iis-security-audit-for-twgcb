using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.AspNetConfiguration;

/// <summary>
/// TWGCB-04-014-0019: httpOnlyCookies
/// </summary>
public class HttpOnlyCookies : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0019";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "True"
        };

        var violatingSites = new List<string>();

        foreach (var site in serverManager.Sites)
        {
            try
            {
                var config = serverManager.GetWebConfiguration(site.Name);
                var section = config.GetSection("system.web/httpCookies");
                
                var httpOnlyCookies = section["httpOnlyCookies"];
                if (httpOnlyCookies == null || !(bool)httpOnlyCookies)
                {
                    violatingSites.Add(site.Name);
                }
            }
            catch { }
        }

        if (violatingSites.Count == 0)
        {
            result.Status = AuditStatus.Pass;
            result.CurrentValue = "True";
            result.Details = "所有站台已啟用 httpOnlyCookies";
        }
        else
        {
            result.Status = AuditStatus.Fail;
            result.CurrentValue = $"{violatingSites.Count} 個站台未啟用";
            result.Details = $"未啟用 httpOnlyCookies 的站台:\n{string.Join("\n", violatingSites)}";
        }

        return result;
    }
}
