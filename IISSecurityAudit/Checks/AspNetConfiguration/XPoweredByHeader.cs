using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.AspNetConfiguration;

/// <summary>
/// TWGCB-04-014-0023: X-Powered-By 標頭
/// </summary>
public class XPoweredByHeader : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0023";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "移除"
        };

        var sitesWithHeader = new List<string>();

        foreach (var site in serverManager.Sites)
        {
            try
            {
                var config = serverManager.GetWebConfiguration(site.Name);
                var section = config.GetSection("system.webServer/httpProtocol");
                var headersCollection = section.GetCollection("customHeaders");
                
                foreach (var header in headersCollection)
                {
                    var name = header["name"]?.ToString();
                    if (name?.Equals("X-Powered-By", StringComparison.OrdinalIgnoreCase) == true)
                    {
                        sitesWithHeader.Add(site.Name);
                        break;
                    }
                }
            }
            catch { }
        }

        if (sitesWithHeader.Count == 0)
        {
            result.Status = AuditStatus.Pass;
            result.CurrentValue = "已移除";
            result.Details = "所有站台已移除 X-Powered-By 標頭";
        }
        else
        {
            result.Status = AuditStatus.Fail;
            result.CurrentValue = $"{sitesWithHeader.Count} 個站台仍有此標頭";
            result.Details = $"仍有 X-Powered-By 標頭的站台:\n{string.Join("\n", sitesWithHeader)}";
        }

        return result;
    }
}
