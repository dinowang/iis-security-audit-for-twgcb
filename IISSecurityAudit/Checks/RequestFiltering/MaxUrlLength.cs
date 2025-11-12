using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.RequestFiltering;

/// <summary>
/// TWGCB-04-014-0026: URL 長度上限
/// </summary>
public class MaxUrlLength : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0026";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "4096 以下,但須大於0"
        };

        try
        {
            var config = serverManager.GetApplicationHostConfiguration();
            var section = config.GetSection("system.webServer/security/requestFiltering");
            var requestLimits = section.GetChildElement("requestLimits");
            
            var maxUrl = requestLimits["maxUrl"];
            if (maxUrl != null)
            {
                int length = Convert.ToInt32(maxUrl);
                
                if (length > 0 && length <= 4096)
                {
                    result.Status = AuditStatus.Pass;
                    result.CurrentValue = length.ToString();
                    result.Details = $"URL 長度上限設定為 {length}，符合規範";
                }
                else if (length == 0)
                {
                    result.Status = AuditStatus.Fail;
                    result.CurrentValue = "0 (無限制)";
                    result.Details = "URL 長度未設限，建議設定適當上限";
                }
                else
                {
                    result.Status = AuditStatus.Fail;
                    result.CurrentValue = length.ToString();
                    result.Details = $"URL 長度上限 {length} 超過建議值 4096";
                }
            }
            else
            {
                result.Status = AuditStatus.Manual;
                result.CurrentValue = "無法讀取";
                result.Details = "無法讀取設定值，請手動檢查";
            }
        }
        catch (Exception ex)
        {
            result.Status = AuditStatus.Error;
            result.ErrorMessage = ex.Message;
        }

        return result;
    }
}
