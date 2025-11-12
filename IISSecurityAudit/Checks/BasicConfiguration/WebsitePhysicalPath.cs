using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.BasicConfiguration;

/// <summary>
/// TWGCB-04-014-0001: 網站內容存放位置
/// 檢查網站實體路徑是否位於非系統磁區
/// </summary>
public class WebsitePhysicalPath : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0001";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "存放在非系統磁區"
        };

        var systemDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
        var violatingSites = new List<string>();

        foreach (var site in serverManager.Sites)
        {
            foreach (var app in site.Applications)
            {
                foreach (var vdir in app.VirtualDirectories)
                {
                    var physicalPath = vdir.PhysicalPath;
                    if (physicalPath.StartsWith(systemDrive, StringComparison.OrdinalIgnoreCase))
                    {
                        violatingSites.Add($"{site.Name} - {physicalPath}");
                    }
                }
            }
        }

        if (violatingSites.Count == 0)
        {
            result.Status = AuditStatus.Pass;
            result.CurrentValue = "所有網站皆存放於非系統磁區";
            result.Details = "檢查通過";
        }
        else
        {
            result.Status = AuditStatus.Fail;
            result.CurrentValue = $"發現 {violatingSites.Count} 個網站位於系統磁區";
            result.Details = $"位於系統磁區的網站:\n{string.Join("\n", violatingSites)}";
        }

        return result;
    }
}
