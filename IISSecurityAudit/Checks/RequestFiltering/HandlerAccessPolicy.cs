using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.RequestFiltering;

/// <summary>
/// TWGCB-04-014-0032: 處理常式權限
/// 檢查處理常式是否同時擁有執行和寫入權限
/// </summary>
public class HandlerAccessPolicy : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0032";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "不能同時擁有執行/指令碼與寫入權限"
        };

        try
        {
            var config = serverManager.GetApplicationHostConfiguration();
            var section = config.GetSection("system.webServer/handlers");
            var handlersCollection = section.GetCollection();
            
            var violatingHandlers = new List<string>();
            
            foreach (var handler in handlersCollection)
            {
                var name = handler["name"]?.ToString();
                var accessPolicy = handler["accessPolicy"]?.ToString();
                
                if (!string.IsNullOrEmpty(accessPolicy))
                {
                    // 檢查是否同時包含 Execute/Script 和 Write 權限
                    var policies = accessPolicy.Split(',').Select(p => p.Trim().ToLower()).ToList();
                    
                    bool hasExecute = policies.Contains("execute") || policies.Contains("script");
                    bool hasWrite = policies.Contains("write");
                    
                    if (hasExecute && hasWrite)
                    {
                        violatingHandlers.Add($"{name} ({accessPolicy})");
                    }
                }
            }

            if (violatingHandlers.Count == 0)
            {
                result.Status = AuditStatus.Pass;
                result.CurrentValue = "符合規範";
                result.Details = $"檢查了 {handlersCollection.Count} 個處理常式，沒有發現同時擁有執行和寫入權限的處理常式";
            }
            else
            {
                result.Status = AuditStatus.Fail;
                result.CurrentValue = $"{violatingHandlers.Count} 個處理常式違反規範";
                result.Details = $"以下處理常式同時擁有執行和寫入權限（可能導致安全風險）:\n" +
                               string.Join("\n", violatingHandlers) +
                               "\n\n建議: 檢查這些處理常式是否確實需要同時擁有兩種權限";
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
