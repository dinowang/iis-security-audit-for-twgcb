using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.RequestFiltering;

/// <summary>
/// TWGCB-04-014-0033: 允許未指定的 ISAPI 模組
/// </summary>
public class AllowUnlistedIsapis : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0033";

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
            var section = config.GetSection("system.webServer/security/isapiCgiRestriction");
            
            var notListedIsapisAllowed = section["notListedIsapisAllowed"];
            
            if (notListedIsapisAllowed != null)
            {
                bool allowed = (bool)notListedIsapisAllowed;
                
                if (!allowed)
                {
                    // 檢查 ISAPI 白名單
                    var restrictionsCollection = section.GetCollection();
                    var allowedIsapis = restrictionsCollection
                        .Where(r => (bool)r["allowed"] == true && r["path"]?.ToString().Contains(".dll") == true)
                        .Select(r => r["description"]?.ToString() ?? r["path"]?.ToString())
                        .ToList();
                    
                    result.Status = AuditStatus.Pass;
                    result.CurrentValue = "False";
                    result.Details = $"已設定不允許未列出的 ISAPI 模組\n" +
                                   $"白名單中的 ISAPI 模組: {allowedIsapis.Count} 個\n" +
                                   $"{(allowedIsapis.Any() ? "已允許: " + string.Join(", ", allowedIsapis.Take(5)) : "")}";
                }
                else
                {
                    result.Status = AuditStatus.Fail;
                    result.CurrentValue = "True";
                    result.Details = "目前允許所有未列出的 ISAPI 模組，建議建立 ISAPI 白名單並設為 false";
                }
            }
            else
            {
                result.Status = AuditStatus.Fail;
                result.CurrentValue = "True（預設）";
                result.Details = "未明確設定，預設為允許所有 ISAPI 模組";
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
