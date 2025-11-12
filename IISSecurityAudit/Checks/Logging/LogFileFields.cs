using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.Logging;

/// <summary>
/// TWGCB-04-014-0037: 記錄檔選取欄位
/// 列出目前選取的 W3C 記錄欄位供審查
/// </summary>
public class LogFileFields : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0037";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "啟用,並依需求選取記錄欄位"
        };

        try
        {
            var config = serverManager.GetApplicationHostConfiguration();
            var sitesSection = config.GetSection("system.applicationHost/sites");
            var siteDefaultsElement = sitesSection.GetChildElement("siteDefaults");
            var logFileElement = siteDefaultsElement.GetChildElement("logFile");
            
            var logFormat = logFileElement["logFormat"]?.ToString();
            
            if (logFormat == "W3c")
            {
                var logExtFileFlags = logFileElement["logExtFileFlags"]?.ToString();
                
                if (!string.IsNullOrEmpty(logExtFileFlags))
                {
                    var fields = logExtFileFlags.Split(',').Select(f => f.Trim()).ToList();
                    
                    // 建議的基本欄位
                    var recommendedFields = new[] {
                        "Date", "Time", "ClientIP", "UserName", "Method", 
                        "UriStem", "UriQuery", "HttpStatus", "Win32Status", 
                        "TimeTaken", "ServerIP", "UserAgent", "Referer"
                    };
                    
                    var missingFields = recommendedFields.Except(fields, StringComparer.OrdinalIgnoreCase).ToList();
                    
                    result.Status = missingFields.Any() ? AuditStatus.Manual : AuditStatus.Pass;
                    result.CurrentValue = $"已選取 {fields.Count} 個欄位";
                    result.Details = $"目前選取的記錄欄位:\n{string.Join(", ", fields)}\n\n" +
                                   $"建議的基本欄位: {string.Join(", ", recommendedFields)}\n" +
                                   (missingFields.Any() 
                                       ? $"\n未選取的建議欄位: {string.Join(", ", missingFields)}\n請評估是否需要這些欄位" 
                                       : "\n所有建議欄位均已選取");
                }
                else
                {
                    result.Status = AuditStatus.Manual;
                    result.CurrentValue = "使用預設欄位";
                    result.Details = "使用預設的記錄欄位設定，建議明確指定所需欄位";
                }
            }
            else
            {
                result.Status = AuditStatus.Manual;
                result.CurrentValue = $"記錄格式: {logFormat}";
                result.Details = $"目前使用 {logFormat} 格式，此檢查僅適用於 W3C 格式";
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
