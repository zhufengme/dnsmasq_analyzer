#!/bin/bash

# DNSmasq数据清理脚本
# 可以单独运行或添加到crontab定期执行

# 脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 配置参数
DATA_DIR="${SCRIPT_DIR}/dnsmasq_data"
PYTHON_SCRIPT="${SCRIPT_DIR}/dnsmasq_analyzer.py"
KEEP_DAYS=${1:-30}  # 从命令行参数获取保留天数，默认30天

echo "========================================"
echo "开始DNSmasq数据清理 - $(date)"
echo "========================================"
echo "数据目录: $DATA_DIR"
echo "保留天数: $KEEP_DAYS 天"
echo ""

# 显示清理前的状态
echo "清理前状态:"
if [ -d "$DATA_DIR" ]; then
    file_count=$(find "$DATA_DIR" -name "dns_data_*.json" | wc -l)
    total_size=$(du -sh "$DATA_DIR" 2>/dev/null | cut -f1)
    echo "  数据文件数量: $file_count"
    echo "  目录大小: $total_size"
else
    echo "  数据目录不存在"
fi

echo ""

# 执行清理
python3 "$PYTHON_SCRIPT" --cleanup-only --data-dir "$DATA_DIR" --keep-days "$KEEP_DAYS"

echo ""
echo "========================================"
echo "数据清理完成 - $(date)"
echo "========================================"