using System.Text;
using IISSecurityAudit.Models;

namespace IISSecurityAudit.Reports;

/// <summary>
/// HTML 報告產生器
/// </summary>
public class HtmlReportGenerator
{
    public void GenerateReport(List<AuditResult> results, string outputPath)
    {
        var html = new StringBuilder();
        
        html.AppendLine("<!DOCTYPE html>");
        html.AppendLine("<html lang=\"zh-TW\">");
        html.AppendLine("<head>");
        html.AppendLine("    <meta charset=\"UTF-8\">");
        html.AppendLine("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        html.AppendLine("    <title>IIS 安全性審核報告 - TWGCB-04-014</title>");
        html.AppendLine("    <style>");
        html.AppendLine(@"
        body {
            font-family: 'Microsoft JhengHei', 'Segoe UI', Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            color: #34495e;
            margin-top: 30px;
        }
        .summary {
            display: flex;
            gap: 20px;
            margin: 20px 0;
        }
        .summary-card {
            flex: 1;
            padding: 20px;
            border-radius: 5px;
            color: white;
            text-align: center;
        }
        .summary-card.pass { background-color: #27ae60; }
        .summary-card.fail { background-color: #e74c3c; }
        .summary-card.manual { background-color: #f39c12; }
        .summary-card.error { background-color: #95a5a6; }
        .summary-card h3 { margin: 0; font-size: 36px; }
        .summary-card p { margin: 5px 0 0 0; }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border: 1px solid #ddd;
        }
        th {
            background-color: #3498db;
            color: white;
            font-weight: bold;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .status {
            padding: 5px 10px;
            border-radius: 3px;
            font-weight: bold;
            display: inline-block;
        }
        .status.Pass { background-color: #d4edda; color: #155724; }
        .status.Fail { background-color: #f8d7da; color: #721c24; }
        .status.Manual { background-color: #fff3cd; color: #856404; }
        .status.Error { background-color: #e2e3e5; color: #383d41; }
        .details {
            font-size: 0.9em;
            color: #666;
            white-space: pre-wrap;
        }
        .metadata {
            background-color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .metadata p {
            margin: 5px 0;
        }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            text-align: center;
            color: #7f8c8d;
        }
    ");
        html.AppendLine("    </style>");
        html.AppendLine("</head>");
        html.AppendLine("<body>");
        html.AppendLine("    <div class=\"container\">");
        
        // 標題
        html.AppendLine("        <h1>IIS 10.0 安全性審核報告</h1>");
        html.AppendLine("        <p>依據：政府組態基準 Microsoft IIS 10.0 TWGCB-04-014 (V1.1)</p>");
        
        // 系統資訊
        html.AppendLine("        <div class=\"metadata\">");
        html.AppendLine($"            <p><strong>伺服器名稱:</strong> {Environment.MachineName}</p>");
        html.AppendLine($"            <p><strong>作業系統:</strong> {Environment.OSVersion}</p>");
        html.AppendLine($"            <p><strong>審核時間:</strong> {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p>");
        html.AppendLine($"            <p><strong>檢查項目總數:</strong> {results.Count}</p>");
        html.AppendLine("        </div>");
        
        // 統計摘要
        var passCount = results.Count(r => r.Status == AuditStatus.Pass);
        var failCount = results.Count(r => r.Status == AuditStatus.Fail);
        var manualCount = results.Count(r => r.Status == AuditStatus.Manual);
        var errorCount = results.Count(r => r.Status == AuditStatus.Error);
        
        html.AppendLine("        <h2>審核結果摘要</h2>");
        html.AppendLine("        <div class=\"summary\">");
        html.AppendLine($"            <div class=\"summary-card pass\"><h3>{passCount}</h3><p>通過</p></div>");
        html.AppendLine($"            <div class=\"summary-card fail\"><h3>{failCount}</h3><p>不符合</p></div>");
        html.AppendLine($"            <div class=\"summary-card manual\"><h3>{manualCount}</h3><p>需手動檢查</p></div>");
        html.AppendLine($"            <div class=\"summary-card error\"><h3>{errorCount}</h3><p>檢查錯誤</p></div>");
        html.AppendLine("        </div>");
        
        // 詳細結果表格
        html.AppendLine("        <h2>詳細檢查結果</h2>");
        html.AppendLine("        <table>");
        html.AppendLine("            <thead>");
        html.AppendLine("                <tr>");
        html.AppendLine("                    <th style=\"width: 50px;\">項次</th>");
        html.AppendLine("                    <th style=\"width: 150px;\">TWGCB ID</th>");
        html.AppendLine("                    <th style=\"width: 100px;\">類別</th>");
        html.AppendLine("                    <th style=\"width: 150px;\">檢查項目</th>");
        html.AppendLine("                    <th style=\"width: 80px;\">狀態</th>");
        html.AppendLine("                    <th style=\"width: 120px;\">期望值</th>");
        html.AppendLine("                    <th style=\"width: 120px;\">實際值</th>");
        html.AppendLine("                    <th>詳細資訊</th>");
        html.AppendLine("                </tr>");
        html.AppendLine("            </thead>");
        html.AppendLine("            <tbody>");
        
        foreach (var result in results.OrderBy(r => r.Rule.ItemNumber))
        {
            html.AppendLine("                <tr>");
            html.AppendLine($"                    <td>{result.Rule.ItemNumber}</td>");
            html.AppendLine($"                    <td>{EscapeHtml(result.Rule.Id)}</td>");
            html.AppendLine($"                    <td>{EscapeHtml(result.Rule.Category)}</td>");
            html.AppendLine($"                    <td>{EscapeHtml(result.Rule.Name)}</td>");
            html.AppendLine($"                    <td><span class=\"status {result.Status}\">{GetStatusText(result.Status)}</span></td>");
            html.AppendLine($"                    <td>{EscapeHtml(result.ExpectedValue)}</td>");
            html.AppendLine($"                    <td>{EscapeHtml(result.CurrentValue)}</td>");
            html.AppendLine($"                    <td class=\"details\">{EscapeHtml(result.Details)}</td>");
            html.AppendLine("                </tr>");
        }
        
        html.AppendLine("            </tbody>");
        html.AppendLine("        </table>");
        
        // 頁尾
        html.AppendLine("        <div class=\"footer\">");
        html.AppendLine("            <p>本報告由 IIS Security Audit Tool 自動產生</p>");
        html.AppendLine($"            <p>報告產生時間: {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p>");
        html.AppendLine("        </div>");
        
        html.AppendLine("    </div>");
        html.AppendLine("</body>");
        html.AppendLine("</html>");
        
        File.WriteAllText(outputPath, html.ToString(), Encoding.UTF8);
        Console.WriteLine($"\n報告已儲存至: {outputPath}");
    }

    private string GetStatusText(AuditStatus status)
    {
        return status switch
        {
            AuditStatus.Pass => "通過",
            AuditStatus.Fail => "不符合",
            AuditStatus.Manual => "手動檢查",
            AuditStatus.Error => "錯誤",
            AuditStatus.NotApplicable => "不適用",
            _ => status.ToString()
        };
    }

    private string EscapeHtml(string text)
    {
        if (string.IsNullOrEmpty(text))
            return string.Empty;
        
        return text
            .Replace("&", "&amp;")
            .Replace("<", "&lt;")
            .Replace(">", "&gt;")
            .Replace("\"", "&quot;")
            .Replace("'", "&#39;");
    }
}
