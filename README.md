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

### Windows (CMD)
```bash
.\venv\Scripts\activate
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

## 例子：如何運行(windows)
```bash
.\venv\Scripts\activate
python client/client.py
python -m server.server
```