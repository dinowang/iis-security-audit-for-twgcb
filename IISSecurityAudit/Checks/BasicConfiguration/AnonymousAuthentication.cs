using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.BasicConfiguration;

/// <summary>
/// TWGCB-04-014-0006: 匿名使用者識別
/// 檢查匿名使用者識別是否設為應用程式集區識別
/// </summary>
public class AnonymousAuthentication : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0006";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "應用程式集區識別"
        };

        var config = serverManager.GetApplicationHostConfiguration();
        var section = config.GetSection("system.webServer/security/authentication/anonymousAuthentication");
        
        var username = section["userName"] as string;
        
        // 空字串或未設定表示使用應用程式集區識別
        if (string.IsNullOrEmpty(username) || username == "")
        {
            result.Status = AuditStatus.Pass;
            result.CurrentValue = "應用程式集區識別";
            result.Details = "匿名驗證已正確設定為使用應用程式集區識別";
        }
        else
        {
            result.Status = AuditStatus.Fail;
            result.CurrentValue = $"使用特定帳戶: {username}";
            result.Details = "匿名驗證未使用應用程式集區識別，建議改為使用應用程式集區識別以提高安全性";
        }

        return result;
    }
}
