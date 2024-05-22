import os
import subprocess
import sys

subnet = sys.argv[1]
try:
    result = subprocess.run(["sudo", "nmap", "-sn", "--traceroute", subnet], 
                            capture_output=True, text=True, check=True)
    # 獲取標準輸出內容
    output = result.stdout
    print(output)
except subprocess.CalledProcessError as e:
    print(f"命令執行失敗: {e}")
    output = e.output

# 如果需要將輸出保存到文件
with open(sys.argv[2], "w") as file:
    file.write(output)