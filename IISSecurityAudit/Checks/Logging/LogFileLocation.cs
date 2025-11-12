using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.Logging;

/// <summary>
/// TWGCB-04-014-0036: IIS 記錄檔位置
/// </summary>
public class LogFileLocation : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0036";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "記錄檔存放至受管制的非系統磁碟區"
        };

        var systemDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
        var sitesOnSystemDrive = new List<string>();

        foreach (var site in serverManager.Sites)
        {
            var logDirectory = site.LogFile.Directory;
            if (!string.IsNullOrEmpty(logDirectory))
            {
                // 展開環境變數
                logDirectory = Environment.ExpandEnvironmentVariables(logDirectory);
                
                if (logDirectory.StartsWith(systemDrive, StringComparison.OrdinalIgnoreCase))
                {
                    sitesOnSystemDrive.Add($"{site.Name} - {logDirectory}");
                }
            }
        }

        if (sitesOnSystemDrive.Count == 0)
        {
            result.Status = AuditStatus.Pass;
            result.CurrentValue = "所有記錄檔皆存放於非系統磁區";
            result.Details = "檢查通過";
        }
        else
        {
            result.Status = AuditStatus.Fail;
            result.CurrentValue = $"{sitesOnSystemDrive.Count} 個站台的記錄檔位於系統磁區";
            result.Details = $"位於系統磁區的記錄檔:\n{string.Join("\n", sitesOnSystemDrive)}";
        }

        return result;
    }
}
