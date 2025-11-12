using IISSecurityAudit.Models;
using Microsoft.Web.Administration;
using Microsoft.Win32;

namespace IISSecurityAudit.Checks.TransportEncryption;

/// <summary>
/// TWGCB-04-014-0048: NULL Cipher
/// </summary>
public class NullCipher : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0048";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "停用"
        };

        try
        {
            var registryPath = @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL";
            
            using (var key = Registry.LocalMachine.OpenSubKey(registryPath))
            {
                if (key == null)
                {
                    // 若登錄檔不存在，預設為停用（較安全）
                    result.Status = AuditStatus.Pass;
                    result.CurrentValue = "停用（預設）";
                    result.Details = "NULL Cipher 預設為停用";
                }
                else
                {
                    var enabled = key.GetValue("Enabled");
                    if (enabled == null || (int)enabled == 0)
                    {
                        result.Status = AuditStatus.Pass;
                        result.CurrentValue = "停用";
                        result.Details = "NULL Cipher 已正確停用";
                    }
                    else
                    {
                        result.Status = AuditStatus.Fail;
                        result.CurrentValue = "啟用";
                        result.Details = $"NULL Cipher 已啟用，這是嚴重的安全風險\n登錄檔: HKLM\\{registryPath}\\Enabled\n目前值: {enabled}\n建議值: 0";
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
