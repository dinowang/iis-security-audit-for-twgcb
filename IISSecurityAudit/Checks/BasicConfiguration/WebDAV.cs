using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.BasicConfiguration;

/// <summary>
/// TWGCB-04-014-0007: WebDAV功能
/// 檢查是否停用 WebDAV 功能
/// </summary>
public class WebDAV : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0007";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "False"
        };

        var enabledSites = new List<string>();

        foreach (var site in serverManager.Sites)
        {
            try
            {
                var config = serverManager.GetWebConfiguration(site.Name);
                var section = config.GetSection("system.webServer/webdav/authoring");
                
                var enabled = section["enabled"];
                if (enabled != null && (bool)enabled)
                {
                    enabledSites.Add(site.Name);
                }
            }
            catch
            {
                // WebDAV module might not be installed
            }
        }

        if (enabledSites.Count == 0)
        {
            result.Status = AuditStatus.Pass;
            result.CurrentValue = "False";
            result.Details = "WebDAV 功能已在所有站台停用或未安裝";
        }
        else
        {
            result.Status = AuditStatus.Fail;
            result.CurrentValue = $"{enabledSites.Count} 個站台啟用 WebDAV";
            result.Details = $"啟用 WebDAV 的站台:\n{string.Join("\n", enabledSites)}";
        }

        return result;
    }
}
