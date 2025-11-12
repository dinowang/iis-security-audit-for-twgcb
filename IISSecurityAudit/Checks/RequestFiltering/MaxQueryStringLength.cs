using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.RequestFiltering;

/// <summary>
/// TWGCB-04-014-0027: 查詢字串上限
/// </summary>
public class MaxQueryStringLength : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0027";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "2048 以下,但須大於0"
        };

        try
        {
            var config = serverManager.GetApplicationHostConfiguration();
            var section = config.GetSection("system.webServer/security/requestFiltering");
            var requestLimits = section.GetChildElement("requestLimits");
            
            var maxQueryString = requestLimits["maxQueryString"];
            if (maxQueryString != null)
            {
                int length = Convert.ToInt32(maxQueryString);
                
                if (length > 0 && length <= 2048)
                {
                    result.Status = AuditStatus.Pass;
                    result.CurrentValue = length.ToString();
                    result.Details = $"查詢字串長度上限設定為 {length}，符合規範";
                }
                else if (length == 0)
                {
                    result.Status = AuditStatus.Fail;
                    result.CurrentValue = "0 (無限制)";
                    result.Details = "查詢字串長度未設限，建議設定適當上限";
                }
                else
                {
                    result.Status = AuditStatus.Fail;
                    result.CurrentValue = length.ToString();
                    result.Details = $"查詢字串長度上限 {length} 超過建議值 2048";
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
