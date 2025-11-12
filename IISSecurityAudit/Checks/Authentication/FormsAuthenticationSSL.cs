using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.Authentication;

/// <summary>
/// TWGCB-04-014-0008: 表單驗證需要 SSL
/// </summary>
public class FormsAuthenticationSSL : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0008";

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
                var section = config.GetSection("system.web/authentication/forms");
                
                var requireSSL = section["requireSSL"];
                if (requireSSL == null || !(bool)requireSSL)
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
            result.Details = "所有站台的表單驗證皆要求 SSL";
        }
        else
        {
            result.Status = AuditStatus.Fail;
            result.CurrentValue = $"{violatingSites.Count} 個站台未要求 SSL";
            result.Details = $"未要求 SSL 的站台:\n{string.Join("\n", violatingSites)}";
        }

        return result;
    }
}
