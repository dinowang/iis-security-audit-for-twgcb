using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.RequestFiltering;

/// <summary>
/// TWGCB-04-014-0025: 允許的內容長度上限
/// </summary>
public class MaxAllowedContentLength : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0025";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "30,000,000 以下,但須大於0"
        };

        try
        {
            var config = serverManager.GetApplicationHostConfiguration();
            var section = config.GetSection("system.webServer/security/requestFiltering");
            var requestLimits = section.GetChildElement("requestLimits");
            
            var maxAllowedContentLength = requestLimits["maxAllowedContentLength"];
            if (maxAllowedContentLength != null)
            {
                long length = Convert.ToInt64(maxAllowedContentLength);
                
                if (length > 0 && length <= 30000000)
                {
                    result.Status = AuditStatus.Pass;
                    result.CurrentValue = length.ToString("N0");
                    result.Details = $"內容長度上限設定為 {length:N0} bytes，符合規範";
                }
                else if (length == 0)
                {
                    result.Status = AuditStatus.Fail;
                    result.CurrentValue = "0 (無限制)";
                    result.Details = "內容長度上限設為 0 (無限制)，建議設定適當上限";
                }
                else
                {
                    result.Status = AuditStatus.Fail;
                    result.CurrentValue = length.ToString("N0");
                    result.Details = $"內容長度上限 {length:N0} 超過建議值 30,000,000";
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
