#!/bin/bash

# DNSmasq日志分析自动化脚本
# 可以添加到crontab中定时执行

# 脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 配置参数
LOG_FILE="/var/log/dnsmasq.log"
OUTPUT_DIR="${SCRIPT_DIR}/reports"
DATA_DIR="${SCRIPT_DIR}/dnsmasq_data"
PYTHON_SCRIPT="${SCRIPT_DIR}/dnsmasq_analyzer.py"

# 创建必要的目录
mkdir -p "$OUTPUT_DIR"
mkdir -p "$DATA_DIR"

# 生成带时间戳的报告文件名
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="${OUTPUT_DIR}/dnsmasq_report_${TIMESTAMP}.html"
LATEST_REPORT="${OUTPUT_DIR}/dnsmasq_report_latest.html"

# 运行Python分析脚本
echo "========================================"
echo "开始DNSmasq日志分析 - $(date)"
echo "========================================"

# 执行分析
python3 "$PYTHON_SCRIPT" \
    --log "$LOG_FILE" \
    --output "$REPORT_FILE" \
    --data-dir "$DATA_DIR" \
    --keep-days 30

# 检查执行结果
if [ $? -eq 0 ]; then
    echo "分析成功完成"
    
    # 创建最新报告的软链接
    ln -sf "$REPORT_FILE" "$LATEST_REPORT"
    echo "最新报告已更新: $LATEST_REPORT"
    
    # 清理30天前的旧报告
    find "$OUTPUT_DIR" -name "dnsmasq_report_*.html" -mtime +30 -delete
    echo "已清理30天前的旧报告"
else
    echo "分析失败，请检查日志"
    exit 1
fi

echo "========================================"
echo "分析完成 - $(date)"
echo "========================================"