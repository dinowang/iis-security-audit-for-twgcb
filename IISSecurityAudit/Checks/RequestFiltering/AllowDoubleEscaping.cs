using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.RequestFiltering;

/// <summary>
/// TWGCB-04-014-0029: 允許雙重逸出
/// </summary>
public class AllowDoubleEscaping : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0029";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "不允許"
        };

        try
        {
            var config = serverManager.GetApplicationHostConfiguration();
            var section = config.GetSection("system.webServer/security/requestFiltering");
            
            var allowDoubleEscaping = section["allowDoubleEscaping"];
            if (allowDoubleEscaping != null)
            {
                bool allowed = (bool)allowDoubleEscaping;
                
                if (!allowed)
                {
                    result.Status = AuditStatus.Pass;
                    result.CurrentValue = "不允許";
                    result.Details = "已正確設定不允許雙重逸出";
                }
                else
                {
                    result.Status = AuditStatus.Fail;
                    result.CurrentValue = "允許";
                    result.Details = "目前允許雙重逸出，建議停用以防止攻擊";
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
