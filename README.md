# DNSmasq Log Analyzer

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)

一个功能强大的DNSmasq日志分析工具，用于分析DNS查询日志并生成美观的HTML报告。支持缓存命中率统计、域名访问频率分析、数据持久化存储、自动清理和基于AI的态势感知分析等功能。特别适用于网络管理员、安全工程师和系统运维人员进行DNS流量监控和安全分析。

## ✨ 主要功能

- 📊 **24小时高频域名排名** - 展示最近24小时内访问频率最高的域名
- 📈 **时间分布分析** - 可视化展示查询在各个小时的分布情况
- 💾 **缓存命中率统计** - 分析DNS缓存性能，包含命中和未命中统计
- 🌐 **上游DNS服务器分析** - 支持端口号识别，分别统计相同IP不同端口的使用情况
- 💽 **数据持久化存储** - 自动保存每日数据，支持跨天统计分析
- 🧹 **自动数据清理** - 防止数据文件无限制增长，可配置保留期限
- 🔄 **幂等性执行** - 支持任意间隔的重复运行，不会重复统计
- 🏆 **历史数据汇总** - 展示最近7天的域名访问排行榜
- 🚫 **智能过滤** - 默认排除.arpa反向DNS查询，专注有意义的域名统计
- 🎨 **美观的HTML报告** - 响应式设计，支持移动端查看
- 🤖 **AI态势感知分析** - 基于DeepSeek大模型的智能异常检测和安全建议 ⭐

## 📋 系统要求

- Python 3.6+
- 对 DNSmasq 日志文件的读取权限
- 支持的操作系统：Linux, macOS, Windows
- 可选：DeepSeek API密钥（用于AI态势感知功能）
- Python依赖包：`requests`（用于AI功能）

### 安装依赖

```bash
# 安装Python依赖
pip3 install requests

# 或使用系统包管理器（Ubuntu/Debian）
sudo apt-get install python3-requests

# 或使用系统包管理器（CentOS/RHEL）
sudo yum install python3-requests
```

## 🚀 快速开始

### 基本使用

```bash
# 克隆项目
git clone https://github.com/your-username/dnsmasq-analyzer
cd dnsmasq-analyzer

# 直接运行分析（使用默认设置）
python3 dnsmasq_analyzer.py

# 指定日志文件路径
python3 dnsmasq_analyzer.py --log /path/to/dnsmasq.log

# 自定义输出文件和数据保留期
python3 dnsmasq_analyzer.py --output my_report.html --keep-days 7

# 包含.arpa反向DNS查询（默认排除）
python3 dnsmasq_analyzer.py --include-arpa
```

### AI功能快速配置

```bash
# 方式1：命令行直接配置（推荐）
python3 dnsmasq_analyzer.py --api-key "your-deepseek-api-key"

# 方式2：交互式配置
python3 dnsmasq_analyzer.py --setup-ai

# 测试AI连接
python3 dnsmasq_analyzer.py --test-ai

# 配置完成后正常运行即包含AI分析
python3 dnsmasq_analyzer.py
```

### 命令行参数

```
用法: dnsmasq_analyzer.py [-h] [-l LOG] [-o OUTPUT] [-d DATA_DIR] 
                         [--keep-days KEEP_DAYS] [--cleanup-only] [--include-arpa]

选项:
  -h, --help            显示帮助信息并退出
  -l LOG, --log LOG     DNSmasq日志文件路径 (默认: /var/log/dnsmasq.log)
  -o OUTPUT, --output OUTPUT
                        输出HTML报告文件名 (默认: dnsmasq_report.html)
  -d DATA_DIR, --data-dir DATA_DIR
                        历史数据存储目录 (默认: ./dnsmasq_data)
  --keep-days KEEP_DAYS 数据文件保留天数 (默认: 30天)
  --cleanup-only        仅执行数据清理，不进行日志分析
  --include-arpa        包含.arpa域名查询 (默认排除反向DNS查询)
  --setup-ai            配置DeepSeek AI分析功能
  --test-ai             测试DeepSeek AI连接
```

## 🔧 自动化部署

### 使用提供的Shell脚本

```bash
# 设置执行权限
chmod +x run_analysis.sh

# 运行分析
./run_analysis.sh
```

### 配置定时任务

1. **编辑crontab**
```bash
crontab -e
```

2. **添加定时任务示例**
```bash
# 每小时执行一次
0 * * * * /path/to/dnsmasq_analyzer/run_analysis.sh >> /var/log/dnsmasq_analyzer.log 2>&1

# 每天凌晨2点执行
0 2 * * * /path/to/dnsmasq_analyzer/run_analysis.sh >> /var/log/dnsmasq_analyzer.log 2>&1

# 每6小时执行一次
0 */6 * * * /path/to/dnsmasq_analyzer/run_analysis.sh >> /var/log/dnsmasq_analyzer.log 2>&1
```

更多定时任务配置示例请参考 `crontab.example` 文件。

## 💾 数据管理

### 数据存储结构

脚本会在指定目录下自动创建数据文件：

```
dnsmasq_data/
├── dns_data_2024-01-01.json    # 每日统计数据
├── dns_data_2024-01-02.json
├── .last_processed_state.json  # 处理状态文件
└── ...
```

### 数据文件内容

每个数据文件包含：
- 域名访问次数统计
- DNS查询类型分布
- 客户端IP统计
- 小时分布数据
- 缓存命中率统计
- 上游DNS服务器使用情况（包含端口号）
- TOP 100域名列表
- 排除的.arpa查询数量统计

### 自动数据清理

为避免数据文件无限制增长，提供了灵活的清理机制：

1. **自动清理**：每次运行时自动清理超过保留期的数据文件
```bash
python3 dnsmasq_analyzer.py  # 默认保留30天
```

2. **手动清理**：
```bash
# 清理超过7天的数据
python3 dnsmasq_analyzer.py --cleanup-only --keep-days 7

# 使用专用清理脚本
./cleanup_data.sh 15  # 保留15天数据
```

3. **定期清理**：
```bash
# 每周日凌晨3点清理数据，保留30天
0 3 * * 0 /path/to/dnsmasq-analyzer/cleanup_data.sh 30
```

## 📊 报告内容

生成的HTML报告包含以下分析内容：

### 统计概览
- 24小时查询总数
- 24小时缓存命中率
- 独立域名数量
- 活跃客户端数
- 7天查询总数和缓存命中率

### AI态势感知分析 🤖
- **智能异常检测** - 基于历史数据对比的查询量异常分析
- **域名访问模式识别** - 识别新出现的高频域名和访问模式变化
- **安全风险评估** - 发现可疑域名和潜在威胁行为
- **专业安全建议** - 根据分析结果提供针对性的防护建议

### 详细分析
- **24小时高频域名TOP 50** - 最近24小时访问最多的域名排行
- **查询时间分布图** - 24小时内各时段的查询活动可视化
- **缓存性能分析** - 缓存命中最多和转发最多的域名统计
- **上游DNS服务器使用情况** - 各上游服务器（含端口）的使用统计
- **7天高频域名TOP 50** - 基于历史数据的长期访问趋势

## ⚙️ 高级配置

### .arpa域名过滤

**什么是.arpa域名？**
- `.arpa`域名用于反向DNS解析，将IP地址转换为域名
- `in-addr.arpa`：IPv4反向解析（如：`100.1.168.192.in-addr.arpa`）
- `ip6.arpa`：IPv6反向解析（如：`1.0.0.0...ip6.arpa`）

**为什么要过滤？**
- 反向DNS查询通常非常频繁，但对域名访问统计分析意义不大
- 过滤后可以更专注于用户真正访问的网站域名统计

**使用方式：**
```bash
# 默认排除.arpa域名（推荐）
python3 dnsmasq_analyzer.py

# 包含.arpa域名进行完整统计
python3 dnsmasq_analyzer.py --include-arpa
```

**统计显示：**
- 排除模式下会显示被排除的.arpa查询数量
- 统计数据中的`arpa_queries_excluded`字段记录排除的查询数

### 支持的DNSmasq日志格式

脚本支持标准的DNSmasq日志格式：
```
Dec 30 12:30:45 dnsmasq[12345]: query[A] domain.com from 192.168.1.1
Dec 30 12:30:45 dnsmasq[12345]: forwarded domain.com to 8.8.8.8#53
Dec 30 12:30:45 dnsmasq[12345]: cached domain.com is 1.2.3.4
```

### 上游DNS服务器端口识别

支持识别和分别统计相同IP地址的不同端口：
- `8.8.8.8#53` 和 `8.8.8.8#5353` 会被识别为不同的上游服务器
- `192.168.1.1#53` 和 `192.168.1.1#5353` 也会分别统计

### 性能优化

- **增量处理**：只处理新增的日志记录，避免重复分析
- **内存管理**：自动限制内存中的哈希记录数量
- **存储优化**：限制保存到文件的记录数量，防止文件过大
- **并发安全**：支持多个实例同时运行而不冲突

## 🔍 故障排除

### 常见问题

1. **权限错误**
```bash
sudo python3 dnsmasq_analyzer.py
```

2. **日志文件不存在**
```bash
python3 dnsmasq_analyzer.py --log /path/to/your/dnsmasq.log
```

3. **清理大量旧数据**
```bash
python3 dnsmasq_analyzer.py --cleanup-only --keep-days 1
```

## 🤖 AI态势感知功能

### 功能特色

AI态势感知功能基于DeepSeek大模型，提供专业级的DNS安全分析：

- **🔍 智能异常检测**：自动识别查询量异常波动和可疑流量模式
- **📈 趋势分析**：基于历史数据对比，识别访问模式变化
- **🛡️ 安全风险评估**：发现潜在威胁域名和异常行为
- **💡 专业建议**：提供针对性的安全防护和优化建议

### AI分析示例

```
🤖 AI态势感知分析

1. 查询量趋势分析：
   - 当前小时查询量：1,245次，较上小时增长15.3%
   - 相比历史平均值偏高23%，需要关注

2. 域名访问模式识别：
   - 检测到googleapis.com访问量异常增加（+156%）
   - 新出现高频域名：example-suspicious.com（可疑）

3. 安全风险评估：
   - 发现3个新的高频域名，建议进行安全检查
   - 缓存命中率正常（92.3%），DNS服务运行稳定

4. 安全建议：
   - 建议对异常域名进行威胁情报查询
   - 可考虑设置特定域名的查询限制
```

### 配置AI功能

需要配置DeepSeek API密钥来启用AI态势感知功能。详细配置步骤请参考：[AI_SETUP.md](AI_SETUP.md)

**快速配置：**
```bash
# 命令行直接配置（推荐）
python3 dnsmasq_analyzer.py --api-key "your-api-key-here"

# 交互式配置API密钥
python3 dnsmasq_analyzer.py --setup-ai

# 测试AI连接
python3 dnsmasq_analyzer.py --test-ai
```

**环境变量配置：**
```bash
export DEEPSEEK_API_KEY="your-api-key-here"
```

## 📂 项目结构

```
dnsmasq-analyzer/
├── dnsmasq_analyzer.py      # 主程序文件
├── AI_SETUP.md             # AI功能详细配置指南
├── README.md               # 项目说明文档
├── LICENSE                 # 开源许可证
├── run_analysis.sh         # 运行脚本
├── cleanup_data.sh         # 数据清理脚本
├── example_ai_setup.sh     # AI配置示例脚本
├── crontab.example         # 定时任务配置示例
└── dnsmasq_data/          # 数据存储目录
    ├── dns_data_YYYY-MM-DD.json    # 每日分析数据
    └── deepseek_config.json        # AI配置文件（可选）
```

## 🔗 相关资源

- **DNSmasq官方文档**：[http://www.thekelleys.org.uk/dnsmasq/doc.html](http://www.thekelleys.org.uk/dnsmasq/doc.html)
- **DeepSeek AI平台**：[https://platform.deepseek.com/](https://platform.deepseek.com/)
- **项目Github**：[https://github.com/your-username/dnsmasq-analyzer](https://github.com/your-username/dnsmasq-analyzer)

## 🤝 贡献指南

欢迎提交Issue和Pull Request！

1. Fork 这个项目
2. 创建您的特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交您的修改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开一个 Pull Request

## 🆘 支持与反馈

- 遇到问题？请查看 [故障排除](#-故障排除) 部分
- 仍有疑问？请提交 [GitHub Issue](https://github.com/your-username/dnsmasq-analyzer/issues)
- 功能建议？欢迎在 [Discussions](https://github.com/your-username/dnsmasq-analyzer/discussions) 中讨论

## ⭐ 如果这个项目对您有帮助，请给个Star！

## 📄 许可证

本项目采用 GNU General Public License v3.0 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。
