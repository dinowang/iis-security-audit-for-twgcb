using System.Text.Json;
using IISSecurityAudit.Models;
using Microsoft.Web.Administration;
using IISSecurityAudit.Checks.BasicConfiguration;
using IISSecurityAudit.Checks.Authentication;
using IISSecurityAudit.Checks.AspNetConfiguration;
using IISSecurityAudit.Checks.RequestFiltering;
using IISSecurityAudit.Checks.Logging;
using IISSecurityAudit.Checks.TransportEncryption;

namespace IISSecurityAudit.Checks;

/// <summary>
/// 安全檢查協調器 - 負責載入規則和執行所有檢查
/// </summary>
public class CheckOrchestrator
{
    private readonly Dictionary<string, ISecurityCheck> _checks = new();
    private readonly List<TwgcbRule> _rules = new();

    public CheckOrchestrator()
    {
        InitializeChecks();
        LoadRules();
    }

    private void InitializeChecks()
    {
        // 基本設定
        RegisterCheck(new WebsitePhysicalPath());
        RegisterCheck(new HostHeader());
        RegisterCheck(new DirectoryBrowsing());
        RegisterCheck(new AppPoolIdentity());
        RegisterCheck(new UniqueAppPool());
        RegisterCheck(new AnonymousAuthentication());
        RegisterCheck(new WebDAV());
        
        // 驗證與授權
        RegisterCheck(new FormsAuthenticationSSL());
        RegisterCheck(new FormsAuthenticationCookieMode());
        RegisterCheck(new FormsAuthenticationCookieProtection());
        RegisterCheck(new BasicAuthenticationSSL());
        
        // ASP.NET 設定
        RegisterCheck(new DebugMode());
        RegisterCheck(new CustomErrors());
        RegisterCheck(new Tracing());
        RegisterCheck(new SessionCookies());
        RegisterCheck(new SessionStateCookieMode());
        RegisterCheck(new HttpOnlyCookies());
        RegisterCheck(new XPoweredByHeader());
        
        // 要求篩選
        RegisterCheck(new HttpTrace());
        RegisterCheck(new MaxAllowedContentLength());
        RegisterCheck(new MaxUrlLength());
        RegisterCheck(new MaxQueryStringLength());
        RegisterCheck(new AllowHighBitCharacters());
        RegisterCheck(new AllowDoubleEscaping());
        RegisterCheck(new AllowUnlistedFileExtensions());
        RegisterCheck(new HandlerAccessPolicy());
        RegisterCheck(new AllowUnlistedIsapis());
        RegisterCheck(new AllowUnlistedCgis());
        
        // 記錄
        RegisterCheck(new LoggingEnabled());
        RegisterCheck(new LogFileLocation());
        RegisterCheck(new LogFileFormat());
        RegisterCheck(new LogFileFields());
        RegisterCheck(new LogEventDestination());
        
        // 傳輸加密 (Registry 檢查)
        RegisterCheck(new SslV2Protocol());
        RegisterCheck(new SslV3Protocol());
        RegisterCheck(new Tls10Protocol());
        RegisterCheck(new Tls11Protocol());
        RegisterCheck(new Tls12Protocol());
        RegisterCheck(new NullCipher());
        RegisterCheck(new DesCipher());
        RegisterCheck(new Rc4Cipher());
        RegisterCheck(new Aes128Cipher());
        RegisterCheck(new Aes256Cipher());
        RegisterCheck(new HstsHeader());
    }

    private void RegisterCheck(ISecurityCheck check)
    {
        _checks[check.SupportedRuleId] = check;
    }

    private void LoadRules()
    {
        try
        {
            var jsonPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "rules.json");
            var json = File.ReadAllText(jsonPath);
            
            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
            };
            
            _rules.AddRange(JsonSerializer.Deserialize<List<TwgcbRule>>(json, options) ?? new List<TwgcbRule>());
            
            Console.WriteLine($"已載入 {_rules.Count} 條規則");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"載入規則檔案失敗: {ex.Message}");
            throw;
        }
    }

    public List<AuditResult> ExecuteAll()
    {
        var results = new List<AuditResult>();
        
        using (var serverManager = new ServerManager())
        {
            Console.WriteLine($"\n開始執行 IIS 安全性審核...");
            Console.WriteLine($"伺服器: {Environment.MachineName}");
            Console.WriteLine($"審核時間: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            Console.WriteLine($"檢查項目總數: {_rules.Count}\n");

            int current = 0;
            foreach (var rule in _rules.OrderBy(r => r.ItemNumber))
            {
                current++;
                Console.Write($"\r[{current}/{_rules.Count}] 檢查中: {rule.Id} - {rule.Name}".PadRight(100));

                ISecurityCheck check;
                if (!_checks.TryGetValue(rule.Id, out check!))
                {
                    // 使用手動檢查處理未實作的項目
                    check = new ManualCheck(rule.Id);
                }

                var result = check.Execute(serverManager, rule);
                results.Add(result);
            }
            
            Console.WriteLine($"\n\n審核完成!");
        }

        return results;
    }

    public List<TwgcbRule> GetAllRules() => _rules;
}
