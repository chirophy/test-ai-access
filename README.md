# test-ai-access
AI检测脚本

# 下载后直接执行
chmod +x test-ai-access.sh  
./test-ai-access.sh  

# 或者一行流（如果你放到自己的 server 上）
curl -sL https://raw.githubusercontent.com/chirophy/test-ai-access/main/test-ai-access.sh | bash  

# 选项
./test-ai-access.sh -t 15   # 超时改 15 秒（网络差的 VPS 用）  
./test-ai-access.sh -4      # 只用 IPv4 测  
./test-ai-access.sh -6      # 只用 IPv6 测  
