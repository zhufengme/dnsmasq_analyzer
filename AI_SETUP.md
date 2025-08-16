# 🤖 DNSmasq Analyzer AI态势感知功能使用指南

本文档介绍如何配置和使用基于DeepSeek大模型的AI态势感知功能。

## ✨ 功能特性

- **智能异常检测**：自动分析DNS查询模式，识别异常流量和潜在威胁
- **态势感知描述**：基于历史数据对比，生成通俗易懂的安全态势分析
- **实时威胁评估**：分析最近1小时、24小时的查询突增和域名访问异常
- **安全建议生成**：根据分析结果提供针对性的安全防护建议

## 🔧 配置步骤

### 1. 获取DeepSeek API密钥

1. 访问 [DeepSeek开放平台](https://platform.deepseek.com/)
2. 注册账户并完成实名认证
3. 进入控制台，创建新的API密钥
4. 复制生成的API密钥（格式类似：`sk-xxxxxxxxxxxxxx`）

### 2. 配置API密钥

#### 方式一：命令行直接配置（推荐）

```bash
python3 dnsmasq_analyzer.py --api-key "your-api-key-here"
```

直接在命令行中设置API密钥，无需交互，适合脚本自动化。

#### 方式二：交互式配置

```bash
python3 dnsmasq_analyzer.py --setup-ai
```

按照提示输入API密钥，系统会自动保存配置。

#### 方式三：环境变量配置

```bash
# 临时设置（当前会话有效）
export DEEPSEEK_API_KEY="your-api-key-here"

# 永久设置（添加到 ~/.bashrc 或 ~/.zshrc）
echo 'export DEEPSEEK_API_KEY="your-api-key-here"' >> ~/.bashrc
source ~/.bashrc
```

#### 方式四：配置文件

在以下任一位置创建配置文件 `deepseek_config.json`：

- `./dnsmasq_data/deepseek_config.json`（项目目录，推荐）
- `~/.config/dnsmasq_analyzer/deepseek_config.json`（用户配置）
- `/etc/dnsmasq_analyzer/deepseek_config.json`（系统配置）

配置文件内容：
```json
{
  "api_key": "your-api-key-here",
  "created_at": "2025-08-17T12:00:00",
  "api_base": "https://api.deepseek.com/v1"
}
```

### 3. 测试连接

```bash
python3 dnsmasq_analyzer.py --test-ai
```

如果配置正确，会显示连接成功信息。

## 📊 使用方法

### 启用AI分析

配置完成后，正常运行分析即可自动启用AI功能：

```bash
# 基本分析（包含AI态势感知）
python3 dnsmasq_analyzer.py

# 指定日志文件
python3 dnsmasq_analyzer.py --log /path/to/dnsmasq.log

# 生成自定义报告
python3 dnsmasq_analyzer.py --output ai_report.html
```

### 查看AI分析结果

AI分析结果会自动集成到HTML报告中，包含：

1. **🤖 AI态势感知分析**部分
2. 基于当前数据的智能分析
3. 异常检测和安全建议

## 🎯 AI分析内容

### 分析维度

- **查询量趋势**：对比历史数据，识别流量异常
- **域名访问模式**：分析热门域名的访问模式变化
- **时间分布异常**：检测非正常时间段的查询突增
- **安全风险评估**：识别可疑域名和潜在威胁

### 输出示例

```
🔍 态势感知分析报告

1. **查询量趋势分析**
   - 当前小时查询量：1,245次，较上小时增长15.3%
   - 相比历史平均值偏高23%，需要关注

2. **域名访问模式识别**
   - 检测到googleapis.com访问量异常增加（+156%）
   - 新出现高频域名：example-suspicious.com（可疑）

3. **安全风险评估**
   - 发现3个新的高频域名，建议进行安全检查
   - 缓存命中率正常（92.3%），DNS服务运行稳定

4. **安全建议**
   - 建议对异常域名进行威胁情报查询
   - 可考虑设置特定域名的查询限制
```

## ⚙️ 高级配置

### 自定义分析参数

AI分析使用的参数可以通过修改源码进行自定义：

```python
# 在 analyze_dns_anomalies 方法中
top_domains_24h = self.today_data['domain_counts'].most_common(20)  # 分析TOP 20域名
historical_data = self.load_historical_data(7)  # 对比最近7天数据
```

### API调用优化

```python
# 在 call_deepseek_api 方法中调整参数
data = {
    'model': 'deepseek-chat',
    'max_tokens': 1000,      # 最大响应长度
    'temperature': 0.7       # 创造性程度（0-1）
}
```

## 🛠️ 故障排除

### 常见问题

1. **API密钥无效**
   ```
   错误：DeepSeek API错误: 401 - Unauthorized
   解决：检查API密钥是否正确，是否已激活
   ```

2. **网络连接失败**
   ```
   错误：DeepSeek API请求失败: Connection timeout
   解决：检查网络连接，确认能访问 api.deepseek.com
   ```

3. **配置文件权限问题**
   ```
   错误：读取配置文件失败
   解决：确保配置文件可读，检查文件权限
   ```

### 调试模式

如需调试API调用，可以在源码中添加详细日志：

```python
# 在 call_deepseek_api 方法中
print(f"发送请求到: {self.deepseek_api_base}/chat/completions")
print(f"请求数据: {json.dumps(data, indent=2)}")
```

## 💰 费用说明

- DeepSeek API采用按使用量计费
- 单次分析大约消耗500-1000 tokens
- 每日运行成本通常在0.01-0.1元之间
- 建议合理控制分析频率以控制成本

## 🔒 安全说明

- API密钥文件会自动设置为600权限（仅用户可读写）
- 不建议将API密钥提交到版本控制系统
- 建议定期轮换API密钥
- 分析数据不会发送敏感信息给第三方

## 📞 支持联系

如遇到问题，请：

1. 检查本文档的故障排除部分
2. 查看项目README.md
3. 提交GitHub Issue
4. 联系DeepSeek技术支持（API相关问题）

---

*最后更新：2025年8月17日*