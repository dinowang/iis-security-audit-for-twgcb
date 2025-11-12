using IISSecurityAudit.Models;
using Microsoft.Web.Administration;
using Microsoft.Win32;

namespace IISSecurityAudit.Checks.TransportEncryption;

/// <summary>
/// TWGCB-04-014-0043: SSLv2
/// </summary>
public class SslV2Protocol : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0043";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "停用"
        };

        try
        {
            var registryPath = @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server";
            
            using (var key = Registry.LocalMachine.OpenSubKey(registryPath))
            {
                if (key == null)
                {
                    // 若登錄檔不存在，預設為啟用
                    result.Status = AuditStatus.Fail;
                    result.CurrentValue = "未明確停用（預設啟用）";
                    result.Details = $"登錄檔路徑不存在: HKLM\\{registryPath}\n建議建立並設定 Enabled=0";
                }
                else
                {
                    var enabled = key.GetValue("Enabled");
                    if (enabled == null || (int)enabled != 0)
                    {
                        result.Status = AuditStatus.Fail;
                        result.CurrentValue = enabled == null ? "未設定（預設啟用）" : "啟用";
                        result.Details = $"SSLv2 尚未停用\n登錄檔: HKLM\\{registryPath}\\Enabled\n目前值: {enabled ?? "未設定"}\n建議值: 0";
                    }
                    else
                    {
                        result.Status = AuditStatus.Pass;
                        result.CurrentValue = "停用";
                        result.Details = "SSLv2 已正確停用";
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
