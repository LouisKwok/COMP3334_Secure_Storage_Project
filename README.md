# 安裝與運行指南

## 1. 建立虛擬環境

### Windows (PowerShell / CMD)
```bash
python -m venv venv
```

### macOS / Linux
```bash
python3 -m venv venv
```

## 2. 啟動 (Activate) 虛擬環境

### Windows (PowerShell)
```bash
.\venv\Scripts\Activate.ps1
```

### Windows (CMD)
```bash
.\venv\Scripts\activate.bat
```

### macOS / Linux (Bash / Zsh)
```bash
source venv/bin/activate
```

## 3. 安裝套件
```bash
pip install -r requirements.txt
```

## 4. 退出 (Deactivate) 虛擬環境
```bash
deactivate
```

## 5. 運行 server
```bash
python -m server.server
```