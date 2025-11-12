using IISSecurityAudit.Models;
using Microsoft.Web.Administration;

namespace IISSecurityAudit.Checks.TransportEncryption;

/// <summary>
/// TWGCB-04-014-0042: HSTS 標頭
/// 檢查 Strict-Transport-Security 標頭設定
/// </summary>
public class HstsHeader : SecurityCheckBase
{
    public override string SupportedRuleId => "TWGCB-04-014-0042";

    protected override AuditResult ExecuteCheck(ServerManager serverManager, TwgcbRule rule)
    {
        var result = new AuditResult
        {
            Rule = rule,
            ExpectedValue = "名稱: Strict-Transport-Security, 值: max-age=31536000; includeSubDomains"
        };

        var sitesWithHSTS = new List<string>();
        var sitesWithoutHSTS = new List<string>();
        var sitesWithWeakHSTS = new List<string>();

        foreach (var site in serverManager.Sites)
        {
            try
            {
                // 只檢查有 HTTPS 繫結的站台
                bool hasHttps = site.Bindings.Any(b => b.Protocol.Equals("https", StringComparison.OrdinalIgnoreCase));
                
                if (!hasHttps)
                {
                    continue; // HSTS 只對 HTTPS 站台有意義
                }

                var config = serverManager.GetWebConfiguration(site.Name);
                var section = config.GetSection("system.webServer/httpProtocol");
                var headersCollection = section.GetCollection("customHeaders");
                
                bool foundHSTS = false;
                string hstsValue = null;
                
                foreach (var header in headersCollection)
                {
                    var name = header["name"]?.ToString();
                    if (name?.Equals("Strict-Transport-Security", StringComparison.OrdinalIgnoreCase) == true)
                    {
                        foundHSTS = true;
                        hstsValue = header["value"]?.ToString();
                        break;
                    }
                }

                if (foundHSTS)
                {
                    // 檢查 HSTS 值的強度
                    if (!string.IsNullOrEmpty(hstsValue))
                    {
                        bool hasMaxAge = hstsValue.Contains("max-age=");
                        bool hasIncludeSubDomains = hstsValue.Contains("includeSubDomains", StringComparison.OrdinalIgnoreCase);
                        
                        // 提取 max-age 值
                        int maxAge = 0;
                        if (hasMaxAge)
                        {
                            var match = System.Text.RegularExpressions.Regex.Match(hstsValue, @"max-age=(\d+)");
                            if (match.Success)
                            {
                                int.TryParse(match.Groups[1].Value, out maxAge);
                            }
                        }
                        
                        // 建議 max-age 至少 1 年 (31536000 秒)
                        if (maxAge >= 31536000 && hasIncludeSubDomains)
                        {
                            sitesWithHSTS.Add($"{site.Name} (max-age={maxAge})");
                        }
                        else
                        {
                            sitesWithWeakHSTS.Add($"{site.Name} ({hstsValue})");
                        }
                    }
                    else
                    {
                        sitesWithWeakHSTS.Add($"{site.Name} (空值)");
                    }
                }
                else
                {
                    sitesWithoutHSTS.Add(site.Name);
                }
            }
            catch
            {
                // 忽略個別站台的錯誤
            }
        }

        var totalHttpsSites = sitesWithHSTS.Count + sitesWithoutHSTS.Count + sitesWithWeakHSTS.Count;
        
        if (totalHttpsSites == 0)
        {
            result.Status = AuditStatus.Manual;
            result.CurrentValue = "無 HTTPS 站台";
            result.Details = "未發現任何 HTTPS 站台，HSTS 標頭僅適用於 HTTPS 站台";
        }
        else if (sitesWithoutHSTS.Count == 0 && sitesWithWeakHSTS.Count == 0)
        {
            result.Status = AuditStatus.Pass;
            result.CurrentValue = "所有 HTTPS 站台皆已正確設定";
            result.Details = $"所有 {totalHttpsSites} 個 HTTPS 站台皆已設定強 HSTS 標頭\n" +
                           $"站台列表:\n{string.Join("\n", sitesWithHSTS)}";
        }
        else
        {
            result.Status = AuditStatus.Fail;
            result.CurrentValue = $"{sitesWithoutHSTS.Count + sitesWithWeakHSTS.Count}/{totalHttpsSites} 個站台設定不足";
            
            var details = new List<string>();
            details.Add($"檢查了 {totalHttpsSites} 個 HTTPS 站台\n");
            
            if (sitesWithHSTS.Any())
            {
                details.Add($"✓ 正確設定 HSTS ({sitesWithHSTS.Count} 個):");
                details.Add(string.Join("\n", sitesWithHSTS.Select(s => $"  {s}")));
                details.Add("");
            }
            
            if (sitesWithWeakHSTS.Any())
            {
                details.Add($"⚠ HSTS 設定不足 ({sitesWithWeakHSTS.Count} 個):");
                details.Add(string.Join("\n", sitesWithWeakHSTS.Select(s => $"  {s}")));
                details.Add("  建議: max-age 應至少為 31536000 (1年) 且包含 includeSubDomains");
                details.Add("");
            }
            
            if (sitesWithoutHSTS.Any())
            {
                details.Add($"✗ 未設定 HSTS ({sitesWithoutHSTS.Count} 個):");
                details.Add(string.Join("\n", sitesWithoutHSTS.Select(s => $"  {s}")));
            }
            
            result.Details = string.Join("\n", details);
        }

        return result;
    }
}
