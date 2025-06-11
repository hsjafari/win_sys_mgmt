# win_sys_mgmt
"""
win_sys_mgmt.py — Unified Windows System‑Management Framework
============================================================
A single‑file proof‑of‑concept that delivers **process management**, **centralised logging**,
**policy enforcement**, **live monitoring UI**, and **network‑load simulation** using WMI
(local) & WinRM (remote).

Author  :  ChatGPT (o3)
Revision :  2025‑06‑10 (Redesign — cleaner layout, blueprinted UI, polished logging)

---------------------------------------------------------------------
Requirements
---------------------------------------------------------------------
> Python ≥ 3.9   ``pip install flask wmi pywinrm psutil rich pywin32``

---------------------------------------------------------------------
Quick Start
---------------------------------------------------------------------
```powershell
# PowerShell (Admin)
$Env:FLASK_APP = 'win_sys_mgmt.py'
python -m flask run --reload  # → http://127.0.0.1:5000/
```
"""
