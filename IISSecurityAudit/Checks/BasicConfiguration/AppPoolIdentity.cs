using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.BasicConfiguration;

/// <summary>
/// TWGCB-04-014-0004: 應用程式集區識別
/// 檢查應用程式集區識別是否設為 ApplicationPoolIdentity
/// </summary>
public class AppPoolIdentity : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0004";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "ApplicationPoolIdentity"
        };

        var violatingPools = new List<string>();

        foreach (var appPool in serverManager.ApplicationPools)
        {
            var identityType = appPool.ProcessModel.IdentityType;
            if (identityType != ProcessModelIdentityType.ApplicationPoolIdentity)
            {
                violatingPools.Add($"{appPool.Name} - {identityType}");
            }
        }

        if (violatingPools.Count == 0)
        {
            result.Status = AuditStatus.Pass;
            result.CurrentValue = "所有應用程式集區皆使用 ApplicationPoolIdentity";
            result.Details = "檢查通過";
        }
        else
        {
            result.Status = AuditStatus.Fail;
            result.CurrentValue = $"發現 {violatingPools.Count} 個應用程式集區未使用 ApplicationPoolIdentity";
            result.Details = $"不符合規範的應用程式集區:\n{string.Join("\n", violatingPools)}";
        }

        return result;
    }
}
