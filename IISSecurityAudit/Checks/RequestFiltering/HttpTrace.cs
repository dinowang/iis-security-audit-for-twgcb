using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.RequestFiltering;

/// <summary>
/// TWGCB-04-014-0020: HTTP TRACE 方法
/// </summary>
public class HttpTrace : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0020";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "False"
        };

        try
        {
            var config = serverManager.GetApplicationHostConfiguration();
            var section = config.GetSection("system.webServer/security/requestFiltering");
            var verbsCollection = section.GetCollection("verbs");
            
            bool traceAllowed = true;
            foreach (var verb in verbsCollection)
            {
                var verbName = verb["verb"]?.ToString()?.ToUpper();
                var allowed = verb["allowed"];
                
                if (verbName == "TRACE" && allowed != null && !(bool)allowed)
                {
                    traceAllowed = false;
                    break;
                }
            }

            if (!traceAllowed)
            {
                result.Status = AuditStatus.Pass;
                result.CurrentValue = "False (已禁用)";
                result.Details = "HTTP TRACE 方法已正確禁用";
            }
            else
            {
                result.Status = AuditStatus.Fail;
                result.CurrentValue = "True (未禁用)";
                result.Details = "HTTP TRACE 方法未禁用,建議在要求篩選中禁用此方法";
            }
        }
        catch (Exception ex)
        {
            result.Status = AuditStatus.Manual;
            result.CurrentValue = "需手動檢查";
            result.Details = $"無法自動檢查: {ex.Message}";
        }

        return result;
    }
}
