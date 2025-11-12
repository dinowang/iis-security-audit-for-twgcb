using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.Authentication;

/// <summary>
/// TWGCB-04-014-0010: 表單驗證 Cookie 保護模式
/// </summary>
public class FormsAuthenticationCookieProtection : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0010";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "All"
        };

        var violatingSites = new List<string>();

        foreach (var site in serverManager.Sites)
        {
            try
            {
                var config = serverManager.GetWebConfiguration(site.Name);
                var section = config.GetSection("system.web/authentication/forms");
                
                var protection = section["protection"]?.ToString();
                if (protection != "All")
                {
                    violatingSites.Add($"{site.Name} ({protection ?? "未設定"})");
                }
            }
            catch { }
        }

        if (violatingSites.Count == 0)
        {
            result.Status = AuditStatus.Pass;
            result.CurrentValue = "All";
            result.Details = "所有站台的 Cookie 保護模式皆設為 All";
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
