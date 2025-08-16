# DNSmasq Log Analyzer

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)

一个功能强大的DNSmasq日志分析工具，用于分析DNS查询日志并生成美观的HTML报告。支持缓存命中率统计、域名访问频率分析、数据持久化存储和自动清理等功能。

## ✨ 主要功能

- 📊 **24小时高频域名排名** - 展示最近24小时内访问频率最高的域名
- 📈 **时间分布分析** - 可视化展示查询在各个小时的分布情况
- 💾 **缓存命中率统计** - 分析DNS缓存性能，包含命中和未命中统计
- 🌐 **上游DNS服务器分析** - 支持端口号识别，分别统计相同IP不同端口的使用情况
- 💽 **数据持久化存储** - 自动保存每日数据，支持跨天统计分析
- 🧹 **自动数据清理** - 防止数据文件无限制增长，可配置保留期限
- 🔄 **幂等性执行** - 支持任意间隔的重复运行，不会重复统计
- 🏆 **历史数据汇总** - 展示最近7天的域名访问排行榜
- 🎨 **美观的HTML报告** - 响应式设计，支持移动端查看

## 📋 系统要求

- Python 3.6+
- 对 DNSmasq 日志文件的读取权限
- 支持的操作系统：Linux, macOS, Windows

## 🚀 快速开始

### 基本使用

```bash
# 克隆项目
git clone https://github.com/zhufengme/dnsmasq_analyzer
cd dnsmasq-analyzer

# 直接运行分析
python3 dnsmasq_analyzer.py

# 指定日志文件路径
python3 dnsmasq_analyzer.py --log /path/to/dnsmasq.log

# 自定义输出文件和数据保留期
python3 dnsmasq_analyzer.py --output my_report.html --keep-days 7
```

### 命令行参数

```
用法: dnsmasq_analyzer.py [-h] [-l LOG] [-o OUTPUT] [-d DATA_DIR] 
                         [--keep-days KEEP_DAYS] [--cleanup-only]

选项:
  -h, --help            显示帮助信息并退出
  -l LOG, --log LOG     DNSmasq日志文件路径 (默认: /var/log/dnsmasq.log)
  -o OUTPUT, --output OUTPUT
                        输出HTML报告文件名 (默认: dnsmasq_report.html)
  -d DATA_DIR, --data-dir DATA_DIR
                        历史数据存储目录 (默认: ./dnsmasq_data)
  --keep-days KEEP_DAYS 数据文件保留天数 (默认: 30天)
  --cleanup-only        仅执行数据清理，不进行日志分析
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

### 详细分析
- **24小时高频域名TOP 50** - 最近24小时访问最多的域名排行
- **查询时间分布图** - 24小时内各时段的查询活动可视化
- **缓存性能分析** - 缓存命中最多和转发最多的域名统计
- **上游DNS服务器使用情况** - 各上游服务器（含端口）的使用统计
- **7天高频域名TOP 50** - 基于历史数据的长期访问趋势

## ⚙️ 高级配置

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

## 📄 许可证

本项目采用 GNU General Public License v3.0 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。
