1. 建立虛擬環境
# Windows (PowerShell / CMD)
python -m venv venv

# macOS / Linux
python3 -m venv venv

2. 啟動 (Activate) 虛擬環境
# Windows (PowerShell)
.\venv\Scripts\Activate.ps1

# Windows (CMD)
.\venv\Scripts\activate.bat

# macOS / Linux (Bash / Zsh)
source venv/bin/activate

3. 安裝套件
pip install -r requirements.txt

4. 退出 (Deactivate) 虛擬環境
deactivate