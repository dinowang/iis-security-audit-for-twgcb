using IISSecurityAudit.Models;
using Microsoft.Web.Administration;
using Microsoft.Win32;

namespace IISSecurityAudit.Checks.TransportEncryption;

/// <summary>
/// TWGCB-04-014-0047: TLS 1.2
/// </summary>
public class Tls12Protocol : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0047";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "啟用"
        };

        try
        {
            var registryPath = @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server";
            
            using (var key = Registry.LocalMachine.OpenSubKey(registryPath))
            {
                if (key == null)
                {
                    // TLS 1.2 在較新的 Windows 版本預設啟用
                    result.Status = AuditStatus.Pass;
                    result.CurrentValue = "啟用（預設）";
                    result.Details = "TLS 1.2 在系統預設啟用";
                }
                else
                {
                    var enabled = key.GetValue("Enabled");
                    if (enabled == null || (int)enabled == 1 || (int)enabled == -1)
                    {
                        result.Status = AuditStatus.Pass;
                        result.CurrentValue = "啟用";
                        result.Details = "TLS 1.2 已正確啟用";
                    }
                    else
                    {
                        result.Status = AuditStatus.Fail;
                        result.CurrentValue = "停用";
                        result.Details = $"TLS 1.2 已被停用\n登錄檔: HKLM\\{registryPath}\\Enabled\n目前值: {enabled}\n建議值: 1 或 -1";
                    }
                }
            }
        }
        catch (Exception ex)
        {
            result.Status = AuditStatus.Error;
            result.ErrorMessage = $"讀取登錄檔時發生錯誤: {ex.Message}";
            result.Details = "請確認具有讀取登錄檔的權限";
        }

        return result;
    }
}
