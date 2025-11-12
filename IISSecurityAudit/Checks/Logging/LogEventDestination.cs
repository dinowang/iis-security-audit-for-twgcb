using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.Logging;

/// <summary>
/// TWGCB-04-014-0039: 記錄事件目的地
/// 檢查是否同時記錄到檔案和 ETW
/// </summary>
public class LogEventDestination : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0039";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "記錄檔和 ETW 事件二者"
        };

        try
        {
            var config = serverManager.GetApplicationHostConfiguration();
            var sitesSection = config.GetSection("system.applicationHost/sites");
            var siteDefaultsElement = sitesSection.GetChildElement("siteDefaults");
            var logFileElement = siteDefaultsElement.GetChildElement("logFile");
            
            var logTargetW3C = logFileElement["logTargetW3C"]?.ToString();
            
            if (!string.IsNullOrEmpty(logTargetW3C))
            {
                var targets = logTargetW3C.Split(',').Select(t => t.Trim()).ToList();
                
                bool hasFile = targets.Contains("File", StringComparer.OrdinalIgnoreCase);
                bool hasETW = targets.Contains("ETW", StringComparer.OrdinalIgnoreCase);
                
                if (hasFile && hasETW)
                {
                    result.Status = AuditStatus.Pass;
                    result.CurrentValue = "檔案和 ETW";
                    result.Details = "已設定同時記錄到檔案和 ETW 事件";
                }
                else if (hasFile)
                {
                    result.Status = AuditStatus.Fail;
                    result.CurrentValue = "僅記錄到檔案";
                    result.Details = "目前僅記錄到檔案，建議同時啟用 ETW 事件記錄以提供更完整的稽核追蹤";
                }
                else if (hasETW)
                {
                    result.Status = AuditStatus.Fail;
                    result.CurrentValue = "僅記錄到 ETW";
                    result.Details = "目前僅記錄到 ETW，建議同時啟用檔案記錄以確保記錄的持久性";
                }
                else
                {
                    result.Status = AuditStatus.Fail;
                    result.CurrentValue = "未知的記錄目的地";
                    result.Details = $"目前設定: {logTargetW3C}";
                }
            }
            else
            {
                result.Status = AuditStatus.Manual;
                result.CurrentValue = "使用預設設定";
                result.Details = "使用預設的記錄目的地（通常為檔案），建議明確設定為同時記錄到檔案和 ETW";
            }
        }
        catch (Exception ex)
        {
            result.Status = AuditStatus.Error;
            result.ErrorMessage = $"檢查時發生錯誤: {ex.Message}";
        }

        return result;
    }
}
