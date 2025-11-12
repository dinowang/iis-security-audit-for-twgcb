using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.BasicConfiguration;

/// <summary>
/// TWGCB-04-014-0003: 瀏覽目錄
/// 檢查是否停用瀏覽目錄功能
/// </summary>
public class DirectoryBrowsing : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0003";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "停用"
        };

        var config = serverManager.GetApplicationHostConfiguration();
        var section = config.GetSection("system.webServer/directoryBrowse");
        
        var enabled = section["enabled"];
        bool isEnabled = enabled != null && (bool)enabled;

        if (!isEnabled)
        {
            result.Status = AuditStatus.Pass;
            result.CurrentValue = "已停用";
            result.Details = "瀏覽目錄功能已正確停用";
        }
        else
        {
            result.Status = AuditStatus.Fail;
            result.CurrentValue = "已啟用";
            result.Details = "瀏覽目錄功能處於啟用狀態，建議停用以提高安全性";
        }

        return result;
    }
}
