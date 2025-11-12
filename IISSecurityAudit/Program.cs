using System.Security.Principal;
using IISSecurityAudit.Checks;
using IISSecurityAudit.Reports;

namespace IISSecurityAudit;

class Program
{
    static int Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        
        Console.WriteLine("=".PadRight(80, '='));
        Console.WriteLine("IIS 10.0 安全性審核工具");
        Console.WriteLine("依據：政府組態基準 TWGCB-04-014 (V1.1)");
        Console.WriteLine("=".PadRight(80, '='));
        Console.WriteLine();

        // 檢查管理員權限
        if (!IsAdministrator())
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("錯誤: 此程式需要系統管理員權限才能執行!");
            Console.WriteLine("請以系統管理員身分執行此程式。");
            Console.ResetColor();
            return 1;
        }

        // 檢查是否為 Windows 系統
        if (!OperatingSystem.IsWindows())
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("錯誤: 此程式僅能在 Windows 系統上執行!");
            Console.ResetColor();
            return 1;
        }

        try
        {
            // 執行審核
            var orchestrator = new CheckOrchestrator();
            var results = orchestrator.ExecuteAll();

            // 產生報告
            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var reportPath = Path.Combine(
                Environment.CurrentDirectory,
                $"IIS_Security_Audit_Report_{timestamp}.html"
            );

            var reportGenerator = new HtmlReportGenerator();
            reportGenerator.GenerateReport(results, reportPath);

            // 顯示摘要
            Console.WriteLine();
            Console.WriteLine("=".PadRight(80, '='));
            Console.WriteLine("審核結果摘要");
            Console.WriteLine("=".PadRight(80, '='));
            
            var passCount = results.Count(r => r.Status == Models.AuditStatus.Pass);
            var failCount = results.Count(r => r.Status == Models.AuditStatus.Fail);
            var manualCount = results.Count(r => r.Status == Models.AuditStatus.Manual);
            var errorCount = results.Count(r => r.Status == Models.AuditStatus.Error);
            
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"✓ 通過: {passCount} 項");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"✗ 不符合: {failCount} 項");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"! 需手動檢查: {manualCount} 項");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine($"? 檢查錯誤: {errorCount} 項");
            Console.ResetColor();
            
            Console.WriteLine();
            Console.WriteLine($"完整報告已儲存至: {reportPath}");
            
            // 嘗試開啟報告
            Console.WriteLine();
            Console.Write("是否要開啟報告? (Y/N): ");
            var key = Console.ReadKey();
            Console.WriteLine();
            
            if (key.Key == ConsoleKey.Y)
            {
                try
                {
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = reportPath,
                        UseShellExecute = true
                    });
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"無法開啟報告: {ex.Message}");
                }
            }

            return failCount > 0 ? 2 : 0;
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"\n執行過程發生錯誤: {ex.Message}");
            Console.WriteLine($"\n詳細資訊:\n{ex}");
            Console.ResetColor();
            return 1;
        }
    }

    static bool IsAdministrator()
    {
        if (!OperatingSystem.IsWindows())
            return false;

        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
}
