using IISSecurityAudit.Models;
using Microsoft.Web.Administration;
using Microsoft.Win32;

namespace IISSecurityAudit.Checks.TransportEncryption;

/// <summary>
/// TWGCB-04-014-0050: RC4 加密套件
/// </summary>
public class Rc4Cipher : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0050";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "停用"
        };

        try
        {
            var ciphers = new[] { "RC4 128/128", "RC4 64/128", "RC4 56/128", "RC4 40/128" };
            var enabledCiphers = new List<string>();
            var checkedCiphers = new List<string>();

            foreach (var cipher in ciphers)
            {
                var registryPath = $@"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\{cipher}";
                
                using (var key = Registry.LocalMachine.OpenSubKey(registryPath))
                {
                    if (key != null)
                    {
                        var enabled = key.GetValue("Enabled");
                        checkedCiphers.Add($"{cipher}: {enabled ?? "未設定"}");
                        
                        if (enabled != null && (int)enabled != 0)
                        {
                            enabledCiphers.Add(cipher);
                        }
                    }
                    else
                    {
                        checkedCiphers.Add($"{cipher}: 登錄檔不存在（預設停用）");
                    }
                }
            }

            if (enabledCiphers.Count == 0)
            {
                result.Status = AuditStatus.Pass;
                result.CurrentValue = "停用";
                result.Details = $"RC4 加密已正確停用\n\n檢查項目:\n{string.Join("\n", checkedCiphers)}";
            }
            else
            {
                result.Status = AuditStatus.Fail;
                result.CurrentValue = $"{enabledCiphers.Count} 個 RC4 加密已啟用";
                result.Details = $"以下 RC4 加密仍處於啟用狀態:\n{string.Join("\n", enabledCiphers)}\n\n建議停用所有 RC4 加密\n\n詳細檢查:\n{string.Join("\n", checkedCiphers)}";
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
