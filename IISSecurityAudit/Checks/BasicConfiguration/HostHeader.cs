using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.BasicConfiguration;

/// <summary>
/// TWGCB-04-014-0002: 主機名稱
/// 檢查每個站台是否都設定主機名稱
/// </summary>
public class HostHeader : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0002";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "每個站台都必須設定主機名稱"
        };

        var sitesWithoutHostHeader = new List<string>();

        foreach (var site in serverManager.Sites)
        {
            var hasHostHeader = false;
            foreach (var binding in site.Bindings)
            {
                if (!string.IsNullOrWhiteSpace(binding.Host))
                {
                    hasHostHeader = true;
                    break;
                }
            }

            if (!hasHostHeader)
            {
                sitesWithoutHostHeader.Add($"{site.Name} (ID: {site.Id})");
            }
        }

        if (sitesWithoutHostHeader.Count == 0)
        {
            result.Status = AuditStatus.Pass;
            result.CurrentValue = "所有站台皆已設定主機名稱";
            result.Details = "檢查通過";
        }
        else
        {
            result.Status = AuditStatus.Fail;
            result.CurrentValue = $"發現 {sitesWithoutHostHeader.Count} 個站台未設定主機名稱";
            result.Details = $"未設定主機名稱的站台:\n{string.Join("\n", sitesWithoutHostHeader)}";
        }

        return result;
    }
}
