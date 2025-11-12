using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.RequestFiltering;

/// <summary>
/// TWGCB-04-014-0031: 允許未列出的副檔名
/// </summary>
public class AllowUnlistedFileExtensions : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0031";

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
            var fileExtensions = section.GetChildElement("fileExtensions");
            
            var allowUnlisted = fileExtensions["allowUnlisted"];
            if (allowUnlisted != null)
            {
                bool allowed = (bool)allowUnlisted;
                
                if (!allowed)
                {
                    // 檢查是否有建立白名單
                    var extensionsCollection = fileExtensions.GetCollection();
                    var allowedExtensions = extensionsCollection
                        .Where(e => (bool)e["allowed"] == true)
                        .Select(e => e["fileExtension"]?.ToString())
                        .ToList();
                    
                    result.Status = AuditStatus.Pass;
                    result.CurrentValue = "不允許";
                    result.Details = $"已設定不允許未列出的副檔名\n" +
                                   $"白名單中的副檔名數量: {allowedExtensions.Count}\n" +
                                   $"前 10 個: {string.Join(", ", allowedExtensions.Take(10))}";
                }
                else
                {
                    result.Status = AuditStatus.Fail;
                    result.CurrentValue = "允許";
                    result.Details = "目前允許所有未列出的副檔名，建議設定副檔名白名單並將 allowUnlisted 設為 false";
                }
            }
            else
            {
                result.Status = AuditStatus.Fail;
                result.CurrentValue = "允許（預設）";
                result.Details = "未明確設定，預設為允許所有副檔名";
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
