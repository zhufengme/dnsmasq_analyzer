#!/usr/bin/env python3

import re
import json
import os
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from pathlib import Path
import argparse
import sys

class DnsmasqAnalyzer:
    def __init__(self, log_file='/var/log/dnsmasq.log', data_dir='./dnsmasq_data', keep_days=30, exclude_arpa=True):
        self.log_file = log_file
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self.keep_days = keep_days  # 保留天数，默认30天
        self.exclude_arpa = exclude_arpa  # 是否排除.arpa域名
        
        # 状态文件，记录上次处理的位置
        self.state_file = self.data_dir / '.last_processed_state.json'
        self.last_processed_time = None
        self.load_state()
        
        # 正则表达式解析dnsmasq日志
        # 格式: Dec 30 12:30:45 dnsmasq[12345]: query[A] domain.com from 192.168.1.1
        self.log_pattern = re.compile(
            r'(\w+\s+\d+\s+\d+:\d+:\d+).*?query\[(\w+)\]\s+([^\s]+)\s+from\s+([^\s]+)'
        )
        
        # 缓存命中的正则表达式
        # 格式: Dec 30 12:30:45 dnsmasq[12345]: cached domain.com is 1.2.3.4
        self.cache_pattern = re.compile(
            r'(\w+\s+\d+\s+\d+:\d+:\d+).*?cached\s+([^\s]+)\s+'
        )
        
        # 转发查询的正则表达式
        # 格式: Dec 30 12:30:45 dnsmasq[12345]: forwarded domain.com to 8.8.8.8
        # 或: Dec 30 12:30:45 dnsmasq[12345]: forwarded domain.com to 8.8.8.8#53
        # 或: Dec 30 12:30:45 dnsmasq[12345]: forwarded domain.com to 192.168.1.1#5353
        self.forward_pattern = re.compile(
            r'(\w+\s+\d+\s+\d+:\d+:\d+).*?forwarded\s+([^\s]+)\s+to\s+([^\s]+(?:#\d+)?)'
        )
        
        # 用于存储当天数据
        self.today_data = {
            'date': datetime.now().strftime('%Y-%m-%d'),
            'queries': [],
            'domain_counts': Counter(),
            'query_types': Counter(),
            'client_ips': Counter(),
            'hourly_stats': defaultdict(int),
            'cache_hits': 0,
            'cache_misses': 0,
            'cached_domains': Counter(),
            'forwarded_domains': Counter(),
            'upstream_servers': Counter(),
            'hourly_cache_stats': defaultdict(lambda: {'hits': 0, 'misses': 0}),
            'processed_lines': set(),  # 用于去重
            'arpa_queries_excluded': 0  # 排除的.arpa查询数量
        }
        
        # 数据恢复状态标志
        self._data_restored = False
        
        # 加载今天已有的数据（如果存在）
        self.load_existing_data()
        
    def is_arpa_domain(self, domain):
        """检查是否为.arpa域名（反向DNS查询）"""
        return domain.endswith('.arpa')
    
    def is_within_analysis_window(self, timestamp):
        """智能的时间窗口检查，处理边界条件"""
        now = datetime.now()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        tomorrow_start = today_start + timedelta(days=1)
        
        # 检查是否在当天范围内（从今天00:00到现在）
        if today_start <= timestamp <= now:
            return True
        
        # 处理跨天情况：如果当前时间是凌晨，可能需要包含昨天晚上的日志
        if now.hour < 2:  # 凌晨2点前
            yesterday_22 = today_start - timedelta(hours=2)  # 昨天22点
            if yesterday_22 <= timestamp < today_start:
                return True
        
        # 扩展窗口：包含最近7天的数据（用于历史日志分析）
        week_ago = today_start - timedelta(days=7)
        if week_ago <= timestamp < today_start:
            return True
        
        # 处理时间戳略微超前的情况（可能的系统时间差异），但不超过明天
        if now < timestamp <= min(now + timedelta(minutes=10), tomorrow_start):
            return True
            
        return False
        
    def parse_timestamp(self, timestamp_str):
        """健壮的时间戳解析方法"""
        current_year = datetime.now().year
        now = datetime.now()
        
        # 尝试多种时间戳格式
        timestamp_formats = [
            # 不包含年份的格式（最常见）
            "%b %d %H:%M:%S",                     # Aug 16 05:00:06
            "%B %d %H:%M:%S",                     # August 16 05:00:06
            # 包含年份的格式
            "%Y %b %d %H:%M:%S",                  # 2025 Aug 16 05:00:06
            "%Y %B %d %H:%M:%S",                  # 2025 August 16 05:00:06
            "%Y-%m-%d %H:%M:%S",                  # 2025-08-16 05:00:06
        ]
        
        for fmt in timestamp_formats:
            try:
                # 根据时间戳是否包含年份来决定处理方式
                if timestamp_str.strip().startswith(('19', '20')):  # 包含年份
                    parsed_time = datetime.strptime(timestamp_str, fmt)
                else:  # 不包含年份，需要添加当前年份
                    if "%Y" in fmt:
                        # 跳过包含年份的格式，因为时间戳不包含年份
                        continue
                    # 解析不含年份的时间戳
                    parsed_time = datetime.strptime(timestamp_str, fmt)
                    # 手动添加年份
                    parsed_time = parsed_time.replace(year=current_year)
                
                # 检查解析的时间是否合理（不超过当前时间太远）
                time_diff = abs((now - parsed_time).total_seconds())
                if time_diff > 366 * 24 * 3600:  # 超过一年
                    # 尝试使用前一年
                    try:
                        adjusted_time = parsed_time.replace(year=current_year - 1)
                        if abs((now - adjusted_time).total_seconds()) <= 366 * 24 * 3600:
                            return adjusted_time
                    except ValueError:
                        pass
                    # 如果调整年份后还是不合理，继续尝试其他格式
                    continue
                
                return parsed_time
            except ValueError:
                continue
        
        # 最后的fallback：使用当前时间，但记录警告
        print(f"警告：无法解析时间戳 '{timestamp_str}'，使用当前时间")
        return now

    def parse_log_line(self, line):
        """解析单行日志"""
        # 检查是否是查询记录
        match = self.log_pattern.search(line)
        if match:
            timestamp_str, query_type, domain, client_ip = match.groups()
            timestamp = self.parse_timestamp(timestamp_str)
            
            return {
                'type': 'query',
                'timestamp': timestamp,
                'query_type': query_type,
                'domain': domain.lower(),
                'client_ip': client_ip,
                'hour': timestamp.hour
            }
        
        # 检查是否是缓存命中记录
        cache_match = self.cache_pattern.search(line)
        if cache_match:
            timestamp_str, domain = cache_match.groups()
            timestamp = self.parse_timestamp(timestamp_str)
            
            return {
                'type': 'cache_hit',
                'timestamp': timestamp,
                'domain': domain.lower(),
                'hour': timestamp.hour
            }
        
        # 检查是否是转发记录
        forward_match = self.forward_pattern.search(line)
        if forward_match:
            timestamp_str, domain, upstream = forward_match.groups()
            timestamp = self.parse_timestamp(timestamp_str)
            
            return {
                'type': 'forward',
                'timestamp': timestamp,
                'domain': domain.lower(),
                'upstream': upstream,
                'hour': timestamp.hour
            }
        
        return None
    
    def load_state(self):
        """加载上次处理状态"""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                    self.last_processed_time = datetime.fromisoformat(state.get('last_processed_time', ''))
                    print(f"上次处理时间: {self.last_processed_time}")
            except Exception as e:
                print(f"加载状态文件失败: {e}")
                self.last_processed_time = None
    
    def save_state(self):
        """保存处理状态"""
        state = {
            'last_processed_time': datetime.now().isoformat(),
            'log_file': self.log_file
        }
        with open(self.state_file, 'w') as f:
            json.dump(state, f, indent=2)
    
    def load_existing_data(self):
        """加载今天已有的数据，避免重复统计"""
        date_str = datetime.now().strftime('%Y-%m-%d')
        data_file = self.data_dir / f"dns_data_{date_str}.json"
        
        if data_file.exists():
            try:
                with open(data_file, 'r') as f:
                    existing_data = json.load(f)
                    
                # 恢复已有的统计数据
                self.today_data['cache_hits'] = existing_data.get('cache_hits', 0)
                self.today_data['cache_misses'] = existing_data.get('cache_misses', 0)
                self.today_data['arpa_queries_excluded'] = existing_data.get('arpa_queries_excluded', 0)
                self.today_data['domain_counts'].update(existing_data.get('domain_counts', {}))
                self.today_data['query_types'].update(existing_data.get('query_types', {}))
                self.today_data['client_ips'].update(existing_data.get('client_ips', {}))
                self.today_data['cached_domains'].update(existing_data.get('cached_domains', {}))
                self.today_data['forwarded_domains'].update(existing_data.get('forwarded_domains', {}))
                self.today_data['upstream_servers'].update(existing_data.get('upstream_servers', {}))
                
                # 恢复小时统计
                for hour, stats in existing_data.get('hourly_cache_stats', {}).items():
                    self.today_data['hourly_cache_stats'][int(hour)] = stats
                for hour, count in existing_data.get('hourly_stats', {}).items():
                    self.today_data['hourly_stats'][int(hour)] = count
                    
                # 恢复已处理的行哈希（用于去重）
                if 'processed_lines_hash' in existing_data:
                    self.today_data['processed_lines'] = set(existing_data['processed_lines_hash'])
                
                # 根据总查询数重建queries列表（用于统计目的）
                total_queries = existing_data.get('total_queries', 0)
                self.today_data['queries'] = [{'type': 'query'}] * total_queries  # 简化的查询记录
                
                # 记录已恢复的状态，避免重复计算
                self._data_restored = True
                    
                print(f"已加载今天的现有数据，继续增量统计")
            except Exception as e:
                print(f"加载现有数据失败: {e}")
    
    def get_line_hash(self, line):
        """生成日志行的唯一标识符（包含时间戳和文件位置信息增强唯一性）"""
        import hashlib
        
        # 提取时间戳信息以增强唯一性
        timestamp_info = ""
        parsed_data = self.parse_log_line(line)
        if parsed_data and 'timestamp' in parsed_data:
            timestamp_info = parsed_data['timestamp'].isoformat()
        
        # 结合原始行内容、时间戳和行长度创建更强的唯一标识
        unique_string = f"{line.strip()}|{timestamp_info}|{len(line)}"
        return hashlib.sha256(unique_string.encode()).hexdigest()[:32]  # 使用SHA256并截取前32位
    
    def analyze_log(self):
        """分析日志文件"""
        if not os.path.exists(self.log_file):
            print(f"日志文件 {self.log_file} 不存在")
            return False
        
        new_records = 0
        duplicate_records = 0
        
        try:
            with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    # 生成行的唯一标识
                    line_hash = self.get_line_hash(line.strip())
                    
                    # 跳过已处理的行
                    if line_hash in self.today_data['processed_lines']:
                        duplicate_records += 1
                        continue
                    
                    data = self.parse_log_line(line)
                    if data and self.is_within_analysis_window(data['timestamp']):
                        # 记录已处理的行
                        self.today_data['processed_lines'].add(line_hash)
                        new_records += 1
                        
                        # 处理查询记录
                        if data['type'] == 'query':
                            # 检查是否为.arpa域名并根据设置决定是否排除
                            if self.exclude_arpa and self.is_arpa_domain(data['domain']):
                                self.today_data['arpa_queries_excluded'] += 1
                            else:
                                self.today_data['queries'].append(data)
                                self.today_data['domain_counts'][data['domain']] += 1
                                self.today_data['query_types'][data['query_type']] += 1
                                self.today_data['client_ips'][data['client_ip']] += 1
                                self.today_data['hourly_stats'][data['hour']] += 1
                        
                        # 处理缓存命中记录
                        elif data['type'] == 'cache_hit':
                            # 检查是否为.arpa域名并根据设置决定是否排除
                            if self.exclude_arpa and self.is_arpa_domain(data['domain']):
                                self.today_data['arpa_queries_excluded'] += 1
                            else:
                                self.today_data['cache_hits'] += 1
                                self.today_data['cached_domains'][data['domain']] += 1
                                self.today_data['hourly_cache_stats'][data['hour']]['hits'] += 1
                        
                        # 处理转发记录（缓存未命中）
                        elif data['type'] == 'forward':
                            # 检查是否为.arpa域名并根据设置决定是否排除
                            if self.exclude_arpa and self.is_arpa_domain(data['domain']):
                                self.today_data['arpa_queries_excluded'] += 1
                            else:
                                self.today_data['cache_misses'] += 1
                                self.today_data['forwarded_domains'][data['domain']] += 1
                                self.today_data['upstream_servers'][data['upstream']] += 1
                                self.today_data['hourly_cache_stats'][data['hour']]['misses'] += 1
            
            # 清理过期的行哈希记录
            self.cleanup_processed_lines_hash()
            
            # 计算缓存命中率
            total_lookups = self.today_data['cache_hits'] + self.today_data['cache_misses']
            if total_lookups > 0:
                cache_hit_rate = (self.today_data['cache_hits'] / total_lookups) * 100
            else:
                cache_hit_rate = 0
            
            print(f"\n统计结果:")
            print(f"  新增记录: {new_records} 条")
            print(f"  跳过重复: {duplicate_records} 条")
            if self.exclude_arpa:
                print(f"  排除.arpa查询: {self.today_data['arpa_queries_excluded']} 条")
            print(f"  查询总数: {len(self.today_data['queries'])} 条")
            print(f"  缓存命中: {self.today_data['cache_hits']} 次")
            print(f"  缓存未命中: {self.today_data['cache_misses']} 次")
            print(f"  缓存命中率: {cache_hit_rate:.2f}%")
            
            # 显示数据目录状态
            total_size, file_count = self.get_data_directory_size()
            size_mb = total_size / 1024 / 1024
            print(f"  数据目录状态: {file_count} 个文件，总大小 {size_mb:.2f} MB")
            
            # 保存处理状态
            self.save_state()
            
            return True
            
        except Exception as e:
            print(f"读取日志文件出错: {e}")
            return False
    
    def save_daily_data(self):
        """保存当天数据到JSON文件"""
        date_str = datetime.now().strftime('%Y-%m-%d')
        data_file = self.data_dir / f"dns_data_{date_str}.json"
        
        # 计算缓存命中率
        total_lookups = self.today_data['cache_hits'] + self.today_data['cache_misses']
        cache_hit_rate = (self.today_data['cache_hits'] / total_lookups * 100) if total_lookups > 0 else 0
        
        # 准备要保存的数据
        save_data = {
            'date': date_str,
            'total_queries': len(self.today_data['queries']),
            'arpa_queries_excluded': self.today_data['arpa_queries_excluded'],
            'domain_counts': dict(self.today_data['domain_counts']),
            'query_types': dict(self.today_data['query_types']),
            'client_ips': dict(self.today_data['client_ips']),
            'hourly_stats': dict(self.today_data['hourly_stats']),
            'top_domains': dict(self.today_data['domain_counts'].most_common(100)),
            'cache_hits': self.today_data['cache_hits'],
            'cache_misses': self.today_data['cache_misses'],
            'cache_hit_rate': cache_hit_rate,
            'cached_domains': dict(self.today_data['cached_domains'].most_common(100)),
            'forwarded_domains': dict(self.today_data['forwarded_domains'].most_common(100)),
            'upstream_servers': dict(self.today_data['upstream_servers']),
            'hourly_cache_stats': dict(self.today_data['hourly_cache_stats']),
            # 保存已处理行的哈希值列表（限制大小避免文件过大）
            'processed_lines_hash': list(self.today_data['processed_lines'])[-10000:] if len(self.today_data['processed_lines']) > 10000 else list(self.today_data['processed_lines']),
            'last_update': datetime.now().isoformat()
        }
        
        with open(data_file, 'w', encoding='utf-8') as f:
            json.dump(save_data, f, indent=2, ensure_ascii=False)
        
        print(f"数据已保存到 {data_file}")
        
        # 执行数据文件清理
        self.cleanup_old_data()
    
    def cleanup_old_data(self):
        """清理过期的数据文件"""
        try:
            current_time = datetime.now()
            cleanup_count = 0
            total_size_cleaned = 0
            
            # 扫描数据目录中的所有json文件
            for file_path in self.data_dir.glob("dns_data_*.json"):
                try:
                    # 从文件名提取日期
                    file_name = file_path.stem
                    if file_name.startswith('dns_data_'):
                        date_str = file_name.replace('dns_data_', '')
                        file_date = datetime.strptime(date_str, '%Y-%m-%d')
                        
                        # 检查是否超过保留期限
                        days_old = (current_time - file_date).days
                        if days_old > self.keep_days:
                            file_size = file_path.stat().st_size
                            file_path.unlink()  # 删除文件
                            cleanup_count += 1
                            total_size_cleaned += file_size
                            print(f"  已删除过期数据文件: {file_path.name} ({days_old}天前)")
                            
                except (ValueError, OSError) as e:
                    print(f"  处理文件 {file_path.name} 时出错: {e}")
                    continue
            
            if cleanup_count > 0:
                size_mb = total_size_cleaned / 1024 / 1024
                print(f"数据清理完成: 删除了 {cleanup_count} 个文件，释放空间 {size_mb:.2f} MB")
            else:
                print(f"数据清理检查完成: 当前所有文件都在 {self.keep_days} 天保留期内")
                
        except Exception as e:
            print(f"数据清理过程中出错: {e}")
    
    def cleanup_processed_lines_hash(self):
        """清理过期的已处理行哈希值，避免内存和存储空间过度占用"""
        # 更智能的清理策略：基于时间戳进行清理，而不是简单的数量限制
        max_hash_count = 20000  # 增加哈希保留数量
        cleanup_threshold = 25000  # 清理触发阈值
        
        if len(self.today_data['processed_lines']) > cleanup_threshold:
            # 保留更多记录以提高幂等性可靠性
            hash_list = list(self.today_data['processed_lines'])
            self.today_data['processed_lines'] = set(hash_list[-max_hash_count:])
            cleaned_count = len(hash_list) - max_hash_count
            print(f"已清理 {cleaned_count} 条过期的行哈希记录，保留最近 {max_hash_count} 条")
    
    def get_data_directory_size(self):
        """获取数据目录的总大小"""
        total_size = 0
        file_count = 0
        
        for file_path in self.data_dir.rglob('*'):
            if file_path.is_file():
                total_size += file_path.stat().st_size
                file_count += 1
        
        return total_size, file_count
    
    def load_historical_data(self, days=7):
        """加载历史数据"""
        historical_data = []
        
        for i in range(days):
            date = datetime.now() - timedelta(days=i)
            date_str = date.strftime('%Y-%m-%d')
            data_file = self.data_dir / f"dns_data_{date_str}.json"
            
            if data_file.exists():
                with open(data_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    historical_data.append(data)
        
        return historical_data
    
    def generate_html_report(self, output_file='dnsmasq_report.html'):
        """生成HTML分析报告"""
        # 获取最近24小时的TOP域名
        top_domains_24h = self.today_data['domain_counts'].most_common(50)
        
        # 计算缓存命中率
        total_lookups = self.today_data['cache_hits'] + self.today_data['cache_misses']
        cache_hit_rate = (self.today_data['cache_hits'] / total_lookups * 100) if total_lookups > 0 else 0
        
        # 获取缓存最多的域名
        top_cached = self.today_data['cached_domains'].most_common(10)
        top_forwarded = self.today_data['forwarded_domains'].most_common(10)
        
        # 加载7天的历史数据（不包括今天）
        historical_data = self.load_historical_data(7)
        
        # 合并历史数据统计（排除今天的数据，避免重复计算）
        all_time_domains = Counter()
        total_queries_7d = 0
        total_cache_hits_7d = 0
        total_cache_misses_7d = 0
        # 7天累计的小时分布统计
        hourly_stats_7d = defaultdict(int)
        today_str = datetime.now().strftime('%Y-%m-%d')
        
        for data in historical_data:
            # 跳过今天的数据，避免重复计算
            if data.get('date') == today_str:
                continue
                
            if 'domain_counts' in data:
                all_time_domains.update(data['domain_counts'])
                total_queries_7d += data.get('total_queries', 0)
                total_cache_hits_7d += data.get('cache_hits', 0)
                total_cache_misses_7d += data.get('cache_misses', 0)
                
                # 累计每个小时的查询数据
                hourly_data = data.get('hourly_stats', {})
                for hour_str, count in hourly_data.items():
                    hourly_stats_7d[int(hour_str)] += count
        
        # 添加当天数据（只添加一次）
        all_time_domains.update(self.today_data['domain_counts'])
        total_queries_7d += len(self.today_data['queries'])
        total_cache_hits_7d += self.today_data['cache_hits']
        total_cache_misses_7d += self.today_data['cache_misses']
        
        # 添加当天的小时统计数据
        for hour, count in self.today_data['hourly_stats'].items():
            hourly_stats_7d[hour] += count
        
        # 计算7天缓存命中率
        total_lookups_7d = total_cache_hits_7d + total_cache_misses_7d
        cache_hit_rate_7d = (total_cache_hits_7d / total_lookups_7d * 100) if total_lookups_7d > 0 else 0
        
        html_content = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNSmasq 日志分析报告</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        .header {{
            text-align: center;
            color: white;
            margin-bottom: 30px;
            padding: 20px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 15px;
            backdrop-filter: blur(10px);
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header .update-time {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        
        .stat-card h3 {{
            color: #666;
            font-size: 0.9em;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .stat-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #333;
        }}
        
        .stat-card .change {{
            font-size: 0.9em;
            color: #4CAF50;
            margin-top: 5px;
        }}
        
        .main-content {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        @media (max-width: 968px) {{
            .main-content {{
                grid-template-columns: 1fr;
            }}
        }}
        
        .card {{
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }}
        
        .card h2 {{
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #f0f0f0;
        }}
        
        .domain-list {{
            max-height: 500px;
            overflow-y: auto;
        }}
        
        .domain-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px;
            margin-bottom: 8px;
            background: #f8f9fa;
            border-radius: 8px;
            transition: background 0.3s ease;
        }}
        
        .domain-item:hover {{
            background: #e9ecef;
        }}
        
        .domain-rank {{
            display: inline-block;
            width: 30px;
            height: 30px;
            line-height: 30px;
            text-align: center;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 50%;
            font-weight: bold;
            margin-right: 15px;
        }}
        
        .domain-name {{
            flex: 1;
            font-weight: 500;
            color: #333;
            word-break: break-all;
        }}
        
        .domain-count {{
            background: #667eea;
            color: white;
            padding: 5px 12px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }}
        
        .chart-container {{
            margin-top: 20px;
            height: 300px;
            position: relative;
        }}
        
        .hourly-chart {{
            display: flex;
            align-items: flex-end;
            height: 250px;
            padding: 10px 0;
            border-left: 2px solid #ddd;
            border-bottom: 2px solid #ddd;
        }}
        
        .hour-bar {{
            flex: 1;
            background: linear-gradient(to top, #667eea, #764ba2);
            margin: 0 2px;
            border-radius: 4px 4px 0 0;
            position: relative;
            transition: opacity 0.3s ease;
        }}
        
        .hour-bar:hover {{
            opacity: 0.8;
        }}
        
        .hour-bar::after {{
            content: attr(data-hour);
            position: absolute;
            bottom: -20px;
            left: 50%;
            transform: translateX(-50%);
            font-size: 10px;
            color: #666;
        }}
        
        .hour-bar::before {{
            content: attr(data-count);
            position: absolute;
            top: -20px;
            left: 50%;
            transform: translateX(-50%);
            font-size: 10px;
            color: #333;
            font-weight: bold;
        }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-top: 20px;
        }}
        
        .info-item {{
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
        }}
        
        .info-item h4 {{
            color: #666;
            margin-bottom: 8px;
            font-size: 0.9em;
        }}
        
        .info-item .value {{
            color: #333;
            font-size: 1.2em;
            font-weight: bold;
        }}
        
        .footer {{
            text-align: center;
            color: white;
            margin-top: 40px;
            padding: 20px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌐 DNSmasq 日志分析报告</h1>
            <div class="update-time">更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>24小时查询总数</h3>
                <div class="value">{len(self.today_data['queries']):,}</div>
            </div>
            <div class="stat-card">
                <h3>24小时缓存命中率</h3>
                <div class="value">{cache_hit_rate:.1f}%</div>
                <div class="change">命中:{self.today_data['cache_hits']:,} / 未中:{self.today_data['cache_misses']:,}</div>
            </div>
            <div class="stat-card">
                <h3>独立域名数</h3>
                <div class="value">{len(self.today_data['domain_counts']):,}</div>
            </div>
            <div class="stat-card">
                <h3>活跃客户端</h3>
                <div class="value">{len(self.today_data['client_ips']):,}</div>
            </div>
            <div class="stat-card">
                <h3>7天查询总数</h3>
                <div class="value">{total_queries_7d:,}</div>
            </div>
            <div class="stat-card">
                <h3>7天缓存命中率</h3>
                <div class="value">{cache_hit_rate_7d:.1f}%</div>
                <div class="change">命中:{total_cache_hits_7d:,} / 未中:{total_cache_misses_7d:,}</div>
            </div>
        </div>
        
        <div class="main-content">
            <div class="card">
                <h2>📊 最近24小时高频访问域名 TOP 50</h2>
                <div class="domain-list">
"""
        
        # 添加TOP域名列表
        for idx, (domain, count) in enumerate(top_domains_24h, 1):
            html_content += f"""
                    <div class="domain-item">
                        <span class="domain-rank">{idx}</span>
                        <span class="domain-name">{domain}</span>
                        <span class="domain-count">{count:,}</span>
                    </div>
"""
        
        html_content += """
                </div>
            </div>
            
            <div class="card">
                <h2>📈 7天累计24小时查询时间分布</h2>
                <div class="chart-container">
                    <div class="hourly-chart">
"""
        
        # 添加小时分布图（使用7天累计数据）
        max_hourly = max(hourly_stats_7d.values()) if hourly_stats_7d else 1
        for hour in range(24):
            count = hourly_stats_7d.get(hour, 0)
            height_percent = (count / max_hourly * 100) if max_hourly > 0 else 0
            html_content += f"""
                        <div class="hour-bar" style="height: {height_percent}%;" data-hour="{hour:02d}" data-count="{count}"></div>
"""
        
        html_content += """
                    </div>
                </div>
                
                <div class="info-grid">
                    <div class="info-item">
                        <h4>最活跃时段</h4>
                        <div class="value">{}</div>
                    </div>
                    <div class="info-item">
                        <h4>平均每小时查询</h4>
                        <div class="value">{}</div>
                    </div>
                    <div class="info-item">
                        <h4>最常见查询类型</h4>
                        <div class="value">{}</div>
                    </div>
                    <div class="info-item">
                        <h4>最活跃客户端</h4>
                        <div class="value">{}</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="card" style="grid-column: 1 / -1;">
            <h2>💾 缓存性能分析</h2>
            <div class="main-content">
                <div>
                    <h3 style="color: #666; margin-bottom: 15px;">🔥 缓存命中最多的域名 TOP 10</h3>
                    <div class="domain-list" style="max-height: 300px;">
""".format(
            f"{max(hourly_stats_7d, key=hourly_stats_7d.get, default=0):02d}:00" if hourly_stats_7d else "N/A",
            f"{total_queries_7d // 24:,}" if total_queries_7d else "0",
            self.today_data['query_types'].most_common(1)[0][0] if self.today_data['query_types'] else "N/A",
            self.today_data['client_ips'].most_common(1)[0][0] if self.today_data['client_ips'] else "N/A"
        )
        
        # 添加缓存命中TOP域名
        for idx, (domain, count) in enumerate(top_cached, 1):
            html_content += f"""
                        <div class="domain-item">
                            <span class="domain-rank">{idx}</span>
                            <span class="domain-name">{domain}</span>
                            <span class="domain-count" style="background: #4CAF50;">{count:,}</span>
                        </div>
"""
        
        html_content += """
                    </div>
                </div>
                <div>
                    <h3 style="color: #666; margin-bottom: 15px;">🔄 转发次数最多的域名 TOP 10</h3>
                    <div class="domain-list" style="max-height: 300px;">
"""
        
        # 添加转发TOP域名
        for idx, (domain, count) in enumerate(top_forwarded, 1):
            html_content += f"""
                        <div class="domain-item">
                            <span class="domain-rank">{idx}</span>
                            <span class="domain-name">{domain}</span>
                            <span class="domain-count" style="background: #FF9800;">{count:,}</span>
                        </div>
"""
        
        html_content += """
                    </div>
                </div>
            </div>
            
            <div class="info-grid" style="margin-top: 20px;">
                <div class="info-item">
                    <h4>上游DNS服务器使用情况</h4>
                    <div class="value" style="font-size: 1em;">
"""
        
        # 添加上游服务器统计
        for server, count in self.today_data['upstream_servers'].most_common(5):
            html_content += f"                        {server}: {count:,} 次<br>"
        
        html_content += """
                    </div>
                </div>
                <div class="info-item">
                    <h4>缓存效率提升</h4>
                    <div class="value">{:.1f}%</div>
                    <small style="color: #666;">减少了 {:.0f}% 的上游查询</small>
                </div>
            </div>
        </div>
""".format(cache_hit_rate, cache_hit_rate)
        
        # 添加7天TOP域名
        html_content += """
        <div class="card" style="grid-column: 1 / -1;">
            <h2>🏆 最近7天高频访问域名 TOP 50</h2>
            <div class="domain-list" style="column-count: 2; column-gap: 20px;">
"""
        
        for idx, (domain, count) in enumerate(all_time_domains.most_common(50), 1):
            html_content += f"""
                <div class="domain-item" style="break-inside: avoid;">
                    <span class="domain-rank">{idx}</span>
                    <span class="domain-name">{domain}</span>
                    <span class="domain-count">{count:,}</span>
                </div>
"""
        
        html_content += """
            </div>
        </div>
        
        <div class="footer">
            <p>DNSmasq Analyzer v1.0 | 数据每日自动更新</p>
            <p>报告生成时间: {}</p>
        </div>
    </div>
</body>
</html>
""".format(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"HTML报告已生成: {output_file}")

def main():
    parser = argparse.ArgumentParser(description='DNSmasq日志分析工具')
    parser.add_argument('-l', '--log', default='/var/log/dnsmasq.log', 
                       help='DNSmasq日志文件路径 (默认: /var/log/dnsmasq.log)')
    parser.add_argument('-o', '--output', default='dnsmasq_report.html',
                       help='输出HTML报告文件名 (默认: dnsmasq_report.html)')
    parser.add_argument('-d', '--data-dir', default='./dnsmasq_data',
                       help='历史数据存储目录 (默认: ./dnsmasq_data)')
    parser.add_argument('--keep-days', type=int, default=30,
                       help='数据文件保留天数 (默认: 30天)')
    parser.add_argument('--cleanup-only', action='store_true',
                       help='仅执行数据清理，不进行日志分析')
    parser.add_argument('--include-arpa', action='store_true',
                       help='包含.arpa域名查询 (默认排除反向DNS查询)')
    
    args = parser.parse_args()
    
    print("=" * 50)
    print("DNSmasq 日志分析工具")
    print("=" * 50)
    
    analyzer = DnsmasqAnalyzer(log_file=args.log, data_dir=args.data_dir, keep_days=args.keep_days, exclude_arpa=not args.include_arpa)
    
    # 如果只是清理模式
    if args.cleanup_only:
        print(f"\n正在清理超过 {args.keep_days} 天的数据文件...")
        analyzer.cleanup_old_data()
        total_size, file_count = analyzer.get_data_directory_size()
        size_mb = total_size / 1024 / 1024
        print(f"清理完成，当前数据目录: {file_count} 个文件，总大小 {size_mb:.2f} MB")
        return
    
    # 分析日志
    print("\n正在分析日志文件...")
    if analyzer.analyze_log():
        # 保存数据
        print("\n正在保存数据...")
        analyzer.save_daily_data()
        
        # 生成报告
        print("\n正在生成HTML报告...")
        analyzer.generate_html_report(output_file=args.output)
        
        print("\n✅ 分析完成!")
        print(f"📊 共分析 {len(analyzer.today_data['queries'])} 条查询记录")
        print(f"📁 历史数据保存在: {args.data_dir}")
        print(f"📄 HTML报告: {args.output}")
    else:
        print("\n❌ 分析失败，请检查日志文件是否存在且有读取权限")
        sys.exit(1)

if __name__ == "__main__":
    main()