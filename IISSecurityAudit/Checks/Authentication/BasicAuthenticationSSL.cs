using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.Authentication;

/// <summary>
/// TWGCB-04-014-0011: 基本驗證需要 SSL
/// </summary>
public class BasicAuthenticationSSL : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0011";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "需要 SSL"
        };

        var violatingSites = new List<string>();

        foreach (var site in serverManager.Sites)
        {
            try
            {
                var config = serverManager.GetWebConfiguration(site.Name);
                var section = config.GetSection("system.webServer/security/authentication/basicAuthentication");
                
                var enabled = section["enabled"];
                if (enabled != null && (bool)enabled)
                {
                    // 基本驗證已啟用，檢查是否需要 SSL
                    var sslFlags = config.GetSection("system.webServer/security/access")["sslFlags"]?.ToString();
                    if (string.IsNullOrEmpty(sslFlags) || !sslFlags.Contains("Ssl"))
                    {
                        violatingSites.Add(site.Name);
                    }
                }
            }
            catch { }
        }

        if (violatingSites.Count == 0)
        {
            result.Status = AuditStatus.Pass;
            result.CurrentValue = "需要 SSL";
            result.Details = "所有啟用基本驗證的站台皆要求 SSL";
        }
        else
        {
            result.Status = AuditStatus.Fail;
            result.CurrentValue = $"{violatingSites.Count} 個站台未要求 SSL";
            result.Details = $"啟用基本驗證但未要求 SSL 的站台:\n{string.Join("\n", violatingSites)}";
        }

        return result;
    }
}
