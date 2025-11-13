# PROMPT

This project is generate by GitHub Copilot CLI with following command and prompt:

1. Prepare the environment variables (or .env file) for Azure Document Intelligence: 
   ```.env
   AZURE_DOCUMENT_INTELLIGENCE_ENDPOINT=https://........cognitiveservices.azure.com/
   AZURE_DOCUMENT_INTELLIGENCE_KEY=......
   ```

2. Command line to run Copilot with all tools and paths allowed:
   ```bash
   copilot --allow-all-tools --allow-all-paths 
   ```

3. Use this prompt to generate the desired code:
   ```prompt
   我要生成一隻環境自檢程式，針對 Windows 上的 IIS Server 進行安全檢測。
   
   檢查的依據來自 政府組態基準 Microsoft IIS 10.0 TWGCB-04-014 (V1.1)，文件下載位置：
   PDF 版：https://download.nics.nat.gov.tw/api/v4/file-service/UploadFile/attachfilegcb/TWGCB-04-014_Microsoft%20IIS%2010%E6%94%BF%E5%BA%9C%E7%B5%84%E6%85%8B%E5%9F%BA%E6%BA%96%E8%AA%AA%E6%98%8E%E6%96%87%E4%BB%B6v1.1_1141002.pdf
   Word 版：https://download.nics.nat.gov.tw/api/v4/file-service/UploadFile/attachfilegcb/TWGCB-04-014_Microsoft%20IIS%2010%E6%94%BF%E5%BA%9C%E7%B5%84%E6%85%8B%E5%9F%BA%E6%BA%96%E8%AA%AA%E6%98%8E%E6%96%87%E4%BB%B6v1.1_1141002.docx
   
   將格式轉換為可處理的 Markdown 格式，重點是列出文件中的所有檢查規則（已知 53 條，有可能新增或刪除）
   可以使用 Azure Document Intelligence 服務進行轉換
   Document Intelligence 的參數
   Endpoint 取自環境變數 AZURE_DOCUMENT_INTELLIGENCE_ENDPOINT
   Key 取自環境變數 AZURE_DOCUMENT_INTELLIGENCE_KEY
   轉換完成後重新排版和調整文本內容，呈現人類可讀性，避免因為排版關係產生無用斷行，並移除轉換過程中產生的雜訊或多餘的空白字元，文件中存有複雜的表格需特別注意表格內容的正確性，這份文件同程式一樣重要要保存
   
   利用整理好的規則實作自檢程式，檢查我的 Windows IIS Server 環境是否符合 政府組態基準 文件描述
   每一個邏輯實作為一個獨立的類別檔案，避免單一過大的原始碼檔案，要避免任何一個單獨的檢核產生例外導致不能跑完報告將
   
   將結果產生產生報告書，檢查項目與順序比照 政府組態基準，包含必要的註解說明，對應到的文件出處位置
   
   請使用 C# 語言進行開發，並使用 .NET 9 或更新版本，編譯為獨立可執行檔
   ```
   