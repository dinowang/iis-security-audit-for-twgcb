using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.RequestFiltering;

/// <summary>
/// TWGCB-04-014-0028: 允許高位元字元
/// </summary>
public class AllowHighBitCharacters : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0028";

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
            
            var allowHighBitCharacters = section["allowHighBitCharacters"];
            if (allowHighBitCharacters != null)
            {
                bool allowed = (bool)allowHighBitCharacters;
                
                if (!allowed)
                {
                    result.Status = AuditStatus.Pass;
                    result.CurrentValue = "不允許";
                    result.Details = "已正確設定不允許高位元字元";
                }
                else
                {
                    result.Status = AuditStatus.Fail;
                    result.CurrentValue = "允許";
                    result.Details = "目前允許高位元字元，建議停用以提高安全性";
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
