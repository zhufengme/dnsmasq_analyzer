#!/bin/bash

# DNSmasq Analyzer AI功能配置示例脚本
# 使用方法: ./example_ai_setup.sh your-api-key-here

echo "=================================================="
echo "DNSmasq Analyzer AI功能配置示例"
echo "=================================================="

# 检查是否提供了API密钥参数
if [ -z "$1" ]; then
    echo "❌ 请提供API密钥作为参数"
    echo "使用方法: $0 your-api-key-here"
    echo ""
    echo "或者使用交互式配置:"
    echo "python3 dnsmasq_analyzer.py --setup-ai"
    exit 1
fi

API_KEY="$1"

echo "🔧 正在配置DeepSeek API密钥..."
python3 dnsmasq_analyzer.py --api-key "$API_KEY"

if [ $? -eq 0 ]; then
    echo ""
    echo "🧪 测试API连接..."
    python3 dnsmasq_analyzer.py --test-ai
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "✅ AI功能配置完成！现在您可以："
        echo "1. 运行标准分析（包含AI态势感知）:"
        echo "   python3 dnsmasq_analyzer.py"
        echo ""
        echo "2. 指定日志文件进行分析:"
        echo "   python3 dnsmasq_analyzer.py --log /path/to/dnsmasq.log"
        echo ""
        echo "3. 生成自定义报告:"
        echo "   python3 dnsmasq_analyzer.py --output ai_report.html"
    else
        echo ""
        echo "⚠️ API配置成功，但连接测试失败"
        echo "请检查API密钥是否正确以及网络连接"
    fi
else
    echo ""
    echo "❌ API配置失败，请检查API密钥格式"
fi

echo ""
echo "📚 更多信息请查看: AI_SETUP.md"