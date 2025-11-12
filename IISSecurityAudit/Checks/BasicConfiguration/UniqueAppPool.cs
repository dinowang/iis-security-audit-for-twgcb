using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.BasicConfiguration;

/// <summary>
/// TWGCB-04-014-0005: 應用程式集區
/// 檢查每個站台是否設定唯一的應用程式集區
/// </summary>
public class UniqueAppPool : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0005";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "每個站台皆設定唯一的應用程式集區"
        };

        var appPoolUsage = new Dictionary<string, List<string>>();

        foreach (var site in serverManager.Sites)
        {
            foreach (var app in site.Applications)
            {
                var poolName = app.ApplicationPoolName;
                if (!appPoolUsage.ContainsKey(poolName))
                {
                    appPoolUsage[poolName] = new List<string>();
                }
                appPoolUsage[poolName].Add($"{site.Name}/{app.Path}");
            }
        }

        var sharedPools = appPoolUsage.Where(kvp => kvp.Value.Count > 1).ToList();

        if (sharedPools.Count == 0)
        {
            result.Status = AuditStatus.Pass;
            result.CurrentValue = "每個站台使用唯一的應用程式集區";
            result.Details = "檢查通過";
        }
        else
        {
            result.Status = AuditStatus.Fail;
            result.CurrentValue = $"發現 {sharedPools.Count} 個應用程式集區被多個站台共用";
            var details = new List<string>();
            foreach (var pool in sharedPools)
            {
                details.Add($"應用程式集區 '{pool.Key}' 被以下站台使用:");
                details.AddRange(pool.Value.Select(s => $"  - {s}"));
            }
            result.Details = string.Join("\n", details);
        }

        return result;
    }
}
