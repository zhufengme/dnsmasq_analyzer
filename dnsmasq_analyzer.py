#!/usr/bin/env python3

import re
import sqlite3
import json
import os
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from pathlib import Path
import argparse
import sys
import requests
import hashlib

class DnsmasqAnalyzer:
    def __init__(self, log_file='/var/log/dnsmasq.log', data_dir='./dnsmasq_data', keep_days=30, exclude_arpa=True):
        self.log_file = log_file
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self.keep_days = keep_days  # 保留天数，默认30天
        self.exclude_arpa = exclude_arpa  # 是否排除.arpa域名
        
        # SQLite 数据库配置
        self.db_file = self.data_dir / 'dnsmasq_analysis.db'
        self.init_database()
        
        # DeepSeek AI配置
        self.deepseek_api_key = self.load_deepseek_config()
        self.deepseek_api_base = "https://api.deepseek.com/v1"
        
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
        
    
    def init_database(self):
        """初始化 SQLite 数据库"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # 创建 DNS 查询记录表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dns_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                line_hash TEXT UNIQUE NOT NULL,
                timestamp DATETIME NOT NULL,
                query_type TEXT NOT NULL,
                domain TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                record_type TEXT NOT NULL,
                date_only DATE NOT NULL,
                hour INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # 创建缓存命中记录表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cache_hits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                line_hash TEXT UNIQUE NOT NULL,
                timestamp DATETIME NOT NULL,
                domain TEXT NOT NULL,
                date_only DATE NOT NULL,
                hour INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # 创建 DNS 转发记录表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dns_forwards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                line_hash TEXT UNIQUE NOT NULL,
                timestamp DATETIME NOT NULL,
                domain TEXT NOT NULL,
                upstream_server TEXT NOT NULL,
                date_only DATE NOT NULL,
                hour INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # 创建索引提高查询性能
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_queries_date ON dns_queries(date_only)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_queries_domain ON dns_queries(domain)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_queries_client ON dns_queries(client_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_queries_hour ON dns_queries(hour)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_queries_timestamp ON dns_queries(timestamp)')
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cache_date ON cache_hits(date_only)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cache_domain ON cache_hits(domain)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cache_hour ON cache_hits(hour)')
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_forwards_date ON dns_forwards(date_only)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_forwards_domain ON dns_forwards(domain)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_forwards_upstream ON dns_forwards(upstream_server)')
        
        conn.commit()
        conn.close()
        
    def get_db_connection(self):
        """获取数据库连接"""
        return sqlite3.connect(self.db_file)
    
    def get_statistics_from_db(self, date_filter=None):
        """从数据库获取统计数据"""
        conn = self.get_db_connection()
        cursor = conn.cursor()
        
        if date_filter is None:
            date_filter = datetime.now().strftime('%Y-%m-%d')
        
        try:
            # 查询总数
            cursor.execute('SELECT COUNT(*) FROM dns_queries WHERE date_only = ?', (date_filter,))
            total_queries = cursor.fetchone()[0]
            
            # 缓存命中数
            cursor.execute('SELECT COUNT(*) FROM cache_hits WHERE date_only = ?', (date_filter,))
            cache_hits = cursor.fetchone()[0]
            
            # 缓存未命中数（转发数）
            cursor.execute('SELECT COUNT(*) FROM dns_forwards WHERE date_only = ?', (date_filter,))
            cache_misses = cursor.fetchone()[0]
            
            # 计算缓存命中率
            total_lookups = cache_hits + cache_misses
            cache_hit_rate = (cache_hits / total_lookups * 100) if total_lookups > 0 else 0
            
            return {
                'total_queries': total_queries,
                'cache_hits': cache_hits,
                'cache_misses': cache_misses,
                'cache_hit_rate': cache_hit_rate,
                'total_lookups': total_lookups
            }
        finally:
            conn.close()
    
    def get_24h_statistics_from_db(self):
        """获取过去24小时的真实统计数据"""
        conn = self.get_db_connection()
        cursor = conn.cursor()
        
        # 计算24小时前的时间
        now = datetime.now()
        hours_24_ago = now - timedelta(hours=24)
        
        try:
            # 过去24小时的查询总数
            cursor.execute('''
                SELECT COUNT(*) FROM dns_queries 
                WHERE timestamp >= ?
            ''', (hours_24_ago,))
            total_queries = cursor.fetchone()[0]
            
            # 过去24小时的缓存命中数
            cursor.execute('''
                SELECT COUNT(*) FROM cache_hits 
                WHERE timestamp >= ?
            ''', (hours_24_ago,))
            cache_hits = cursor.fetchone()[0]
            
            # 过去24小时的缓存未命中数
            cursor.execute('''
                SELECT COUNT(*) FROM dns_forwards 
                WHERE timestamp >= ?
            ''', (hours_24_ago,))
            cache_misses = cursor.fetchone()[0]
            
            # 计算缓存命中率
            total_lookups = cache_hits + cache_misses
            cache_hit_rate = (cache_hits / total_lookups * 100) if total_lookups > 0 else 0
            
            return {
                'total_queries': total_queries,
                'cache_hits': cache_hits,
                'cache_misses': cache_misses,
                'cache_hit_rate': cache_hit_rate,
                'total_lookups': total_lookups
            }
        finally:
            conn.close()
    
    def get_top_domains_from_db(self, date_filter=None, limit=50):
        """从数据库获取高频域名"""
        conn = self.get_db_connection()
        cursor = conn.cursor()
        
        if date_filter is None:
            date_filter = datetime.now().strftime('%Y-%m-%d')
        
        try:
            cursor.execute('''
                SELECT domain, COUNT(*) as count
                FROM dns_queries 
                WHERE date_only = ?
                GROUP BY domain 
                ORDER BY count DESC 
                LIMIT ?
            ''', (date_filter, limit))
            
            return cursor.fetchall()
        finally:
            conn.close()
    
    def get_top_domains_24h_from_db(self, limit=50):
        """从数据库获取过去24小时的高频域名"""
        conn = self.get_db_connection()
        cursor = conn.cursor()
        
        # 计算24小时前的时间
        now = datetime.now()
        hours_24_ago = now - timedelta(hours=24)
        
        try:
            cursor.execute('''
                SELECT domain, COUNT(*) as count
                FROM dns_queries 
                WHERE timestamp >= ?
                GROUP BY domain 
                ORDER BY count DESC 
                LIMIT ?
            ''', (hours_24_ago, limit))
            
            return cursor.fetchall()
        finally:
            conn.close()
    
    def get_hourly_stats_from_db(self, days=1):
        """从数据库获取按小时统计的数据"""
        conn = self.get_db_connection()
        cursor = conn.cursor()
        
        end_date = datetime.now().strftime('%Y-%m-%d')
        start_date = (datetime.now() - timedelta(days=days-1)).strftime('%Y-%m-%d')
        
        try:
            cursor.execute('''
                SELECT hour, COUNT(*) as count
                FROM dns_queries 
                WHERE date_only BETWEEN ? AND ?
                GROUP BY hour 
                ORDER BY hour
            ''', (start_date, end_date))
            
            # 转换为字典格式
            hourly_stats = {}
            for hour, count in cursor.fetchall():
                hourly_stats[hour] = count
            
            return hourly_stats
        finally:
            conn.close()
    
    def get_client_stats_from_db(self, date_filter=None, limit=6):
        """从数据库获取客户端统计数据"""
        conn = self.get_db_connection()
        cursor = conn.cursor()
        
        if date_filter is None:
            date_filter = datetime.now().strftime('%Y-%m-%d')
        
        try:
            # 获取最活跃的客户端
            cursor.execute('''
                SELECT client_ip, COUNT(*) as count
                FROM dns_queries 
                WHERE date_only = ?
                GROUP BY client_ip 
                ORDER BY count DESC 
                LIMIT ?
            ''', (date_filter, limit))
            
            top_clients = cursor.fetchall()
            
            # 获取每个客户端的高频域名
            result = []
            for client_ip, total_queries in top_clients:
                cursor.execute('''
                    SELECT domain, COUNT(*) as count
                    FROM dns_queries 
                    WHERE date_only = ? AND client_ip = ?
                    GROUP BY domain 
                    ORDER BY count DESC 
                    LIMIT 10
                ''', (date_filter, client_ip))
                
                top_domains = cursor.fetchall()
                result.append({
                    'client_ip': client_ip,
                    'total_queries': total_queries,
                    'top_domains': top_domains
                })
            
            return result
        finally:
            conn.close()
    
    def get_client_stats_24h_from_db(self, limit=6):
        """从数据库获取过去24小时的客户端统计数据"""
        conn = self.get_db_connection()
        cursor = conn.cursor()
        
        # 计算24小时前的时间
        now = datetime.now()
        hours_24_ago = now - timedelta(hours=24)
        
        try:
            # 获取最活跃的客户端
            cursor.execute('''
                SELECT client_ip, COUNT(*) as count
                FROM dns_queries 
                WHERE timestamp >= ?
                GROUP BY client_ip 
                ORDER BY count DESC 
                LIMIT ?
            ''', (hours_24_ago, limit))
            
            top_clients = cursor.fetchall()
            
            # 获取每个客户端的高频域名
            result = []
            for client_ip, total_queries in top_clients:
                cursor.execute('''
                    SELECT domain, COUNT(*) as count
                    FROM dns_queries 
                    WHERE timestamp >= ? AND client_ip = ?
                    GROUP BY domain 
                    ORDER BY count DESC 
                    LIMIT 10
                ''', (hours_24_ago, client_ip))
                
                top_domains = cursor.fetchall()
                result.append({
                    'client_ip': client_ip,
                    'total_queries': total_queries,
                    'top_domains': top_domains
                })
            
            return result
        finally:
            conn.close()
    
    def get_cache_stats_from_db(self, date_filter=None, limit=10):
        """从数据库获取缓存统计数据"""
        conn = self.get_db_connection()
        cursor = conn.cursor()
        
        if date_filter is None:
            date_filter = datetime.now().strftime('%Y-%m-%d')
        
        try:
            # 获取缓存命中最多的域名
            cursor.execute('''
                SELECT domain, COUNT(*) as count
                FROM cache_hits 
                WHERE date_only = ?
                GROUP BY domain 
                ORDER BY count DESC 
                LIMIT ?
            ''', (date_filter, limit))
            top_cached = cursor.fetchall()
            
            # 获取转发最多的域名
            cursor.execute('''
                SELECT domain, COUNT(*) as count
                FROM dns_forwards 
                WHERE date_only = ?
                GROUP BY domain 
                ORDER BY count DESC 
                LIMIT ?
            ''', (date_filter, limit))
            top_forwarded = cursor.fetchall()
            
            # 获取上游服务器统计
            cursor.execute('''
                SELECT upstream_server, COUNT(*) as count
                FROM dns_forwards 
                WHERE date_only = ?
                GROUP BY upstream_server 
                ORDER BY count DESC 
                LIMIT ?
            ''', (date_filter, limit))
            upstream_servers = cursor.fetchall()
            
            return {
                'top_cached': top_cached,
                'top_forwarded': top_forwarded,
                'upstream_servers': upstream_servers
            }
        finally:
            conn.close()
    
    def get_multi_day_stats_from_db(self, days=7):
        """从数据库获取多天统计数据"""
        conn = self.get_db_connection()
        cursor = conn.cursor()
        
        end_date = datetime.now().strftime('%Y-%m-%d')
        start_date = (datetime.now() - timedelta(days=days-1)).strftime('%Y-%m-%d')
        
        try:
            # 获取多天高频域名
            cursor.execute('''
                SELECT domain, COUNT(*) as count
                FROM dns_queries 
                WHERE date_only BETWEEN ? AND ?
                GROUP BY domain 
                ORDER BY count DESC 
                LIMIT 50
            ''', (start_date, end_date))
            top_domains = cursor.fetchall()
            
            # 获取总统计
            cursor.execute('''
                SELECT COUNT(*) FROM dns_queries 
                WHERE date_only BETWEEN ? AND ?
            ''', (start_date, end_date))
            total_queries = cursor.fetchone()[0]
            
            cursor.execute('''
                SELECT COUNT(*) FROM cache_hits 
                WHERE date_only BETWEEN ? AND ?
            ''', (start_date, end_date))
            total_cache_hits = cursor.fetchone()[0]
            
            cursor.execute('''
                SELECT COUNT(*) FROM dns_forwards 
                WHERE date_only BETWEEN ? AND ?
            ''', (start_date, end_date))
            total_cache_misses = cursor.fetchone()[0]
            
            # 获取按小时的统计
            hourly_stats = self.get_hourly_stats_from_db(days)
            
            total_lookups = total_cache_hits + total_cache_misses
            cache_hit_rate = (total_cache_hits / total_lookups * 100) if total_lookups > 0 else 0
            
            return {
                'top_domains': top_domains,
                'total_queries': total_queries,
                'total_cache_hits': total_cache_hits,
                'total_cache_misses': total_cache_misses,
                'cache_hit_rate': cache_hit_rate,
                'hourly_stats': hourly_stats
            }
        finally:
            conn.close()
        
    def load_deepseek_config(self):
        """加载DeepSeek API配置"""
        # 按优先级依次检查配置源
        
        # 1. 环境变量
        api_key = os.getenv('DEEPSEEK_API_KEY')
        if api_key:
            return api_key
        
        # 2. 配置文件
        config_paths = [
            self.data_dir / 'deepseek_config.json',
            Path.home() / '.config' / 'dnsmasq_analyzer' / 'deepseek_config.json',
            Path('/etc/dnsmasq_analyzer/deepseek_config.json')
        ]
        
        for config_path in config_paths:
            if config_path.exists():
                try:
                    with open(config_path, 'r') as f:
                        config = json.load(f)
                        if 'api_key' in config:
                            return config['api_key']
                except Exception as e:
                    print(f"读取配置文件失败 {config_path}: {e}")
        
        return None
    
    def setup_deepseek_config(self, api_key=None):
        """设置DeepSeek API配置"""
        if api_key is None:
            # 交互式设置
            print("\n=== DeepSeek AI 配置设置 ===")
            print("请按照以下步骤获取API密钥：")
            print("1. 访问 https://platform.deepseek.com/")
            print("2. 注册并登录账户")
            print("3. 在控制台创建API密钥")
            print("4. 复制API密钥并粘贴到下方")
            print()
            
            api_key = input("请输入您的DeepSeek API密钥: ").strip()
        
        if not api_key:
            print("❌ API密钥不能为空")
            return False
        
        # 验证API密钥格式
        if not api_key.startswith('sk-'):
            print("⚠️ 警告：API密钥格式可能不正确，通常以 'sk-' 开头")
        
        # 保存配置
        config_dir = self.data_dir
        config_file = config_dir / 'deepseek_config.json'
        
        config = {
            'api_key': api_key,
            'created_at': datetime.now().isoformat(),
            'api_base': self.deepseek_api_base
        }
        
        try:
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            # 设置文件权限为只有用户可读写
            os.chmod(config_file, 0o600)
            
            print(f"✅ 配置已保存到: {config_file}")
            print("💡 提示：您也可以设置环境变量 DEEPSEEK_API_KEY 来配置API密钥")
            
            self.deepseek_api_key = api_key
            return True
            
        except Exception as e:
            print(f"❌ 保存配置失败: {e}")
            return False

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
    
    def get_line_hash(self, line):
        """生成日志行的唯一标识符（包含时间戳和文件位置信息增强唯一性）"""
        # 提取时间戳信息以增强唯一性
        timestamp_info = ""
        parsed_data = self.parse_log_line(line)
        if parsed_data and 'timestamp' in parsed_data:
            timestamp_info = parsed_data['timestamp'].isoformat()
        
        # 结合原始行内容、时间戳和行长度创建更强的唯一标识
        unique_string = f"{line.strip()}|{timestamp_info}|{len(line)}"
        return hashlib.sha256(unique_string.encode()).hexdigest()[:32]  # 使用SHA256并截取前32位
    
    def markdown_to_html(self, markdown_text):
        """将markdown文本转换为HTML格式"""
        if not markdown_text:
            return ""
        
        # 转义HTML特殊字符（但保留换行符用于后续处理）
        html_text = markdown_text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        
        # 先处理代码块和行内代码，避免被其他规则干扰
        # 处理代码块 ```
        html_text = re.sub(r'```(\w+)?\n(.*?)\n```', 
                          r'<pre><code>\2</code></pre>', 
                          html_text, flags=re.DOTALL)
        
        # 处理行内代码 `code` (避免与粗体斜体冲突)
        html_text = re.sub(r'`([^`]+)`', r'<code>\1</code>', html_text)
        
        # 处理粗体 **text** 或 __text__
        html_text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', html_text)
        html_text = re.sub(r'__(.*?)__', r'<strong>\1</strong>', html_text)
        
        # 处理斜体 *text* 或 _text_ (注意避免与列表冲突)
        html_text = re.sub(r'(?<!\*)\*([^*\n]+)\*(?!\*)', r'<em>\1</em>', html_text)
        html_text = re.sub(r'(?<!_)_([^_\n]+)_(?!_)', r'<em>\1</em>', html_text)
        
        # 按段落分割处理
        paragraphs = html_text.split('\n\n')
        processed_paragraphs = []
        
        for para in paragraphs:
            para = para.strip()
            if not para:
                continue
                
            lines = para.split('\n')
            processed_lines = []
            in_list = False
            list_items = []
            
            current_list_type = None  # 'ul' for unordered, 'ol' for ordered
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                    
                # 处理标题
                if line.startswith('####'):
                    if in_list:
                        list_tag = current_list_type or 'ul'
                        processed_lines.append(f'<{list_tag}>{"".join(list_items)}</{list_tag}>')
                        list_items = []
                        in_list = False
                        current_list_type = None
                    processed_lines.append(f'<h4>{line[4:].strip()}</h4>')
                elif line.startswith('###'):
                    if in_list:
                        list_tag = current_list_type or 'ul'
                        processed_lines.append(f'<{list_tag}>{"".join(list_items)}</{list_tag}>')
                        list_items = []
                        in_list = False
                        current_list_type = None
                    processed_lines.append(f'<h3>{line[3:].strip()}</h3>')
                elif line.startswith('##'):
                    if in_list:
                        list_tag = current_list_type or 'ul'
                        processed_lines.append(f'<{list_tag}>{"".join(list_items)}</{list_tag}>')
                        list_items = []
                        in_list = False
                        current_list_type = None
                    processed_lines.append(f'<h2>{line[2:].strip()}</h2>')
                elif line.startswith('#'):
                    if in_list:
                        list_tag = current_list_type or 'ul'
                        processed_lines.append(f'<{list_tag}>{"".join(list_items)}</{list_tag}>')
                        list_items = []
                        in_list = False
                        current_list_type = None
                    processed_lines.append(f'<h1>{line[1:].strip()}</h1>')
                
                # 处理无序列表项
                elif line.startswith('- ') or line.startswith('* '):
                    if in_list and current_list_type == 'ol':
                        # 如果前面是有序列表，先关闭
                        processed_lines.append(f'<ol>{"".join(list_items)}</ol>')
                        list_items = []
                    content = line[2:].strip()
                    list_items.append(f'<li>{content}</li>')
                    in_list = True
                    current_list_type = 'ul'
                
                # 处理有序列表项 - 修复问题：支持更灵活的有序列表格式
                elif re.match(r'^\d+[\.\)]\s+', line):
                    if in_list and current_list_type == 'ul':
                        # 如果前面是无序列表，先关闭
                        processed_lines.append(f'<ul>{"".join(list_items)}</ul>')
                        list_items = []
                    # 移除数字和标点符号（点号或括号）
                    content = re.sub(r'^\d+[\.\)]\s+', '', line)
                    list_items.append(f'<li>{content}</li>')
                    in_list = True
                    current_list_type = 'ol'
                
                # 普通文本行
                else:
                    if in_list:
                        list_tag = current_list_type or 'ul'
                        processed_lines.append(f'<{list_tag}>{"".join(list_items)}</{list_tag}>')
                        list_items = []
                        in_list = False
                        current_list_type = None
                    processed_lines.append(line)
            
            # 处理段落结束时的列表
            if in_list and list_items:
                list_tag = current_list_type or 'ul'
                processed_lines.append(f'<{list_tag}>{"".join(list_items)}</{list_tag}>')
            
            # 将非HTML标签的连续行包装为段落
            if processed_lines:
                para_content = '\n'.join(processed_lines)
                
                # 分离HTML标签和普通文本
                html_elements = []
                current_text = []
                
                for line in processed_lines:
                    if re.match(r'^\s*<(?:h[1-6]|ul|ol|pre)', line):
                        # 如果之前有普通文本，包装为段落
                        if current_text:
                            text_content = ' '.join(current_text)
                            html_elements.append(f'<p>{text_content}</p>')
                            current_text = []
                        html_elements.append(line)
                    else:
                        current_text.append(line)
                
                # 处理剩余的普通文本
                if current_text:
                    text_content = ' '.join(current_text)
                    html_elements.append(f'<p>{text_content}</p>')
                
                processed_paragraphs.extend(html_elements)
        
        # 组合结果
        result = '\n'.join(processed_paragraphs)
        
        # 清理多余的空白和换行
        result = re.sub(r'\n\s*\n', '\n', result)
        result = result.strip()
        
        return result

    def call_deepseek_api(self, prompt, max_tokens=1000):
        """调用DeepSeek API进行AI分析"""
        if not self.deepseek_api_key:
            return None
        
        headers = {
            'Authorization': f'Bearer {self.deepseek_api_key}',
            'Content-Type': 'application/json'
        }
        
        data = {
            'model': 'deepseek-chat',
            'messages': [
                {
                    'role': 'system',
                    'content': '你是一个专业的网络安全分析师，专门分析DNS查询日志，识别异常行为和潜在威胁。请用中文回答，语言简洁明了。请严格按照以下要求输出纯文本内容：\n- 只输出纯文本，不使用任何markdown格式符号\n- 不使用 #、*、-、[] 等markdown标记\n- 使用阿拉伯数字和中文标点符号进行结构化输出\n- 重要内容可以用中文描述词强调，如"重点关注"、"需要注意"\n- 保持内容简洁明了，避免格式混乱'
                },
                {
                    'role': 'user',
                    'content': prompt
                }
            ],
            'max_tokens': max_tokens,
            'temperature': 0.7
        }
        
        try:
            response = requests.post(
                f"{self.deepseek_api_base}/chat/completions",
                headers=headers,
                json=data,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                if 'choices' in result and len(result['choices']) > 0:
                    return result['choices'][0]['message']['content']
            else:
                print(f"DeepSeek API错误: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"DeepSeek API请求失败: {e}")
            return None
        except Exception as e:
            print(f"DeepSeek API调用异常: {e}")
            return None
    
    def analyze_dns_anomalies(self):
        """分析DNS查询异常"""
        if not self.deepseek_api_key:
            return {"status": "no_api_key", "message": "未配置DeepSeek API密钥"}
        
        # 获取当前小时和最近1小时的数据
        now = datetime.now()
        current_hour = now.hour
        last_hour = (now - timedelta(hours=1)).hour
        
        # 从数据库获取当前数据
        today_str = datetime.now().strftime('%Y-%m-%d')
        hourly_stats = self.get_hourly_stats_from_db(1)
        
        # 分析最近1小时的查询突增
        current_hour_queries = hourly_stats.get(current_hour, 0)
        last_hour_queries = hourly_stats.get(last_hour, 0)
        
        # 获取最近24小时最活跃的域名
        top_domains_24h = self.get_top_domains_24h_from_db(20)
        
        # 获取查询量最高的6个客户端及其高频域名
        top_clients_with_domains = self.get_client_stats_24h_from_db(6)
        
        # 获取历史数据进行对比
        multi_day_stats = self.get_multi_day_stats_from_db(7)
        historical_averages = {
            'avg_total_queries': multi_day_stats['total_queries'] / 7,
            'avg_hourly': {h: c / 7 for h, c in multi_day_stats['hourly_stats'].items()},
            'historical_days': 7
        }
        
        # 构建分析提示
        prompt = self.build_analysis_prompt(
            current_hour_queries, last_hour_queries, top_domains_24h, 
            historical_averages, current_hour, top_clients_with_domains
        )
        
        # 调用AI分析
        ai_analysis = self.call_deepseek_api(prompt)
        
        if ai_analysis:
            return {
                "status": "success",
                "analysis": ai_analysis,
                "timestamp": now.isoformat(),
                "data_summary": {
                    "current_hour_queries": current_hour_queries,
                    "last_hour_queries": last_hour_queries,
                    "top_domains_count": len(top_domains_24h),
                    "total_domains_24h": len(top_domains_24h)
                }
            }
        else:
            return {"status": "api_error", "message": "AI分析调用失败"}
    
    
    def build_analysis_prompt(self, current_hour_queries, last_hour_queries, 
                            top_domains, historical_averages, current_hour, top_clients_with_domains=None):
        """构建AI分析提示"""
        
        # 计算查询变化率
        if last_hour_queries > 0:
            change_rate = ((current_hour_queries - last_hour_queries) / last_hour_queries) * 100
        else:
            change_rate = 100 if current_hour_queries > 0 else 0
        
        # 获取历史平均值进行对比
        hist_avg_current = historical_averages.get('avg_hourly', {}).get(current_hour, 0)
        hist_avg_last = historical_averages.get('avg_hourly', {}).get((current_hour-1) % 24, 0)
        
        prompt = f"""
请分析以下DNS查询数据，提供态势感知描述：

时间信息：
- 当前时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} (第{current_hour}小时)
- 分析时段：最近1小时

查询量统计：
- 当前小时查询量：{current_hour_queries:,} 次
- 上一小时查询量：{last_hour_queries:,} 次
- 变化率：{change_rate:+.1f}%

历史对比（基于过去{historical_averages.get('historical_days', 0)}天数据）：
- 当前小时历史平均：{hist_avg_current:.0f} 次
- 上一小时历史平均：{hist_avg_last:.0f} 次

最近24小时TOP域名：
"""
        
        for i, (domain, count) in enumerate(top_domains[:10], 1):
            prompt += f"{i}. {domain}: {count:,} 次查询\n"
        
        # 添加客户端域名分析数据
        if top_clients_with_domains:
            prompt += f"\n最活跃的6个客户端及其高频域名：\n"
            for i, client_data in enumerate(top_clients_with_domains, 1):
                client_ip = client_data['client_ip']
                total_queries = client_data['total_queries']
                top_domains_client = client_data['top_domains'][:5]  # 只显示前5个域名
                
                prompt += f"{i}. {client_ip} ({total_queries:,} 次查询):\n"
                for j, (domain, count) in enumerate(top_domains_client, 1):
                    percentage = (count / total_queries * 100) if total_queries > 0 else 0
                    prompt += f"   {j}. {domain}: {count:,} 次 ({percentage:.1f}%)\n"
        
        prompt += f"""
请基于以上数据提供态势感知分析，包括：
1. 查询量趋势分析（是否异常）
2. 域名访问模式识别
3. 客户端行为分析（是否有异常集中或可疑活动）
4. 可能的安全风险或异常行为
5. 简要的安全建议

请用简洁的中文回答，重点突出异常情况和安全关注点。如果一切正常，请说明当前网络活动正常。请使用纯文本格式输出，便于直接显示。
"""
        
        return prompt
    
    def analyze_log(self):
        """分析日志文件并写入数据库"""
        if not os.path.exists(self.log_file):
            print(f"日志文件 {self.log_file} 不存在")
            return False
        
        new_records = 0
        duplicate_records = 0
        arpa_excluded = 0
        
        conn = self.get_db_connection()
        cursor = conn.cursor()
        
        try:
            # 开始事务
            conn.execute('BEGIN TRANSACTION')
            
            with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    # 生成行的唯一标识
                    line_hash = self.get_line_hash(line.strip())
                    
                    # 检查是否已处理（查询数据库）
                    cursor.execute('''
                        SELECT 1 FROM dns_queries WHERE line_hash = ?
                        UNION ALL
                        SELECT 1 FROM cache_hits WHERE line_hash = ?
                        UNION ALL
                        SELECT 1 FROM dns_forwards WHERE line_hash = ?
                        LIMIT 1
                    ''', (line_hash, line_hash, line_hash))
                    
                    if cursor.fetchone():
                        duplicate_records += 1
                        continue
                    
                    data = self.parse_log_line(line)
                    if data and self.is_within_analysis_window(data['timestamp']):
                        # 检查是否为.arpa域名并根据设置决定是否排除
                        if self.exclude_arpa and self.is_arpa_domain(data['domain']):
                            arpa_excluded += 1
                            continue
                        
                        date_str = data['timestamp'].strftime('%Y-%m-%d')
                        hour = data['timestamp'].hour
                        
                        try:
                            # 处理查询记录
                            if data['type'] == 'query':
                                cursor.execute('''
                                    INSERT OR IGNORE INTO dns_queries 
                                    (line_hash, timestamp, query_type, domain, client_ip, record_type, date_only, hour)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                                ''', (line_hash, data['timestamp'], data['type'], data['domain'], 
                                      data['client_ip'], data['query_type'], date_str, hour))
                                
                            # 处理缓存命中记录
                            elif data['type'] == 'cache_hit':
                                cursor.execute('''
                                    INSERT OR IGNORE INTO cache_hits 
                                    (line_hash, timestamp, domain, date_only, hour)
                                    VALUES (?, ?, ?, ?, ?)
                                ''', (line_hash, data['timestamp'], data['domain'], date_str, hour))
                                
                            # 处理转发记录（缓存未命中）
                            elif data['type'] == 'forward':
                                cursor.execute('''
                                    INSERT OR IGNORE INTO dns_forwards 
                                    (line_hash, timestamp, domain, upstream_server, date_only, hour)
                                    VALUES (?, ?, ?, ?, ?, ?)
                                ''', (line_hash, data['timestamp'], data['domain'], 
                                      data['upstream'], date_str, hour))
                            
                            if cursor.rowcount > 0:
                                new_records += 1
                                
                        except sqlite3.IntegrityError:
                            # 重复记录，忽略
                            duplicate_records += 1
                            continue
            
            # 提交事务
            conn.commit()
            
            # 获取统计数据
            stats = self.get_statistics_from_db()
            
            print(f"\n统计结果:")
            print(f"  新增记录: {new_records} 条")
            print(f"  跳过重复: {duplicate_records} 条")
            if self.exclude_arpa:
                print(f"  排除.arpa查询: {arpa_excluded} 条")
            print(f"  查询总数: {stats['total_queries']} 条")
            print(f"  缓存命中: {stats['cache_hits']} 次")
            print(f"  缓存未命中: {stats['cache_misses']} 次")
            print(f"  缓存命中率: {stats['cache_hit_rate']:.2f}%")
            
            # 显示数据库状态
            db_size = os.path.getsize(self.db_file) / 1024 / 1024
            print(f"  数据库大小: {db_size:.2f} MB")
            
            # 保存处理状态
            self.save_state()
            
            return True
            
        except Exception as e:
            # 回滚事务
            conn.rollback()
            print(f"分析日志文件出错: {e}")
            return False
        finally:
            conn.close()
    
    
    def cleanup_old_data(self):
        """清理过期的数据库记录"""
        try:
            current_time = datetime.now()
            cutoff_date = (current_time - timedelta(days=self.keep_days)).strftime('%Y-%m-%d')
            
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            # 删除过期记录
            cursor.execute('DELETE FROM dns_queries WHERE date_only < ?', (cutoff_date,))
            queries_deleted = cursor.rowcount
            
            cursor.execute('DELETE FROM cache_hits WHERE date_only < ?', (cutoff_date,))
            cache_deleted = cursor.rowcount
            
            cursor.execute('DELETE FROM dns_forwards WHERE date_only < ?', (cutoff_date,))
            forwards_deleted = cursor.rowcount
            
            conn.commit()
            
            total_deleted = queries_deleted + cache_deleted + forwards_deleted
            if total_deleted > 0:
                print(f"数据清理完成: 删除了 {total_deleted} 条过期记录 (超过 {self.keep_days} 天)")
                print(f"  查询记录: {queries_deleted} 条")
                print(f"  缓存记录: {cache_deleted} 条")
                print(f"  转发记录: {forwards_deleted} 条")
                
                # 优化数据库
                cursor.execute('VACUUM')
                conn.commit()
                print("数据库已优化")
            else:
                print(f"数据清理检查完成: 当前所有数据都在 {self.keep_days} 天保留期内")
                
            conn.close()
        except Exception as e:
            print(f"数据清理过程中出错: {e}")
    
    
    
    
    
    def generate_html_report(self, output_file='dnsmasq_report.html'):
        """生成HTML分析报告"""
        # 从数据库获取数据
        today_str = datetime.now().strftime('%Y-%m-%d')
        
        # 获取最近24小时的TOP域名
        top_domains_24h = self.get_top_domains_24h_from_db(50)
        
        # 获取查询量最高的6个客户端及其TOP 10域名
        top_clients_with_domains = self.get_client_stats_24h_from_db(6)
        
        # 获取24小时和当天的统计数据
        stats_24h = self.get_24h_statistics_from_db()
        today_stats = self.get_statistics_from_db(today_str)
        cache_hit_rate = stats_24h['cache_hit_rate']
        
        # 获取缓存统计数据
        cache_stats = self.get_cache_stats_from_db(today_str, 10)
        top_cached = cache_stats['top_cached']
        top_forwarded = cache_stats['top_forwarded']
        upstream_servers = cache_stats['upstream_servers']
        
        # 执行AI态势感知分析
        ai_analysis_result = self.analyze_dns_anomalies()
        
        # 获取7天的统计数据
        multi_day_stats = self.get_multi_day_stats_from_db(7)
        all_time_domains = multi_day_stats['top_domains']
        total_queries_7d = multi_day_stats['total_queries']
        total_cache_hits_7d = multi_day_stats['total_cache_hits']
        total_cache_misses_7d = multi_day_stats['total_cache_misses']
        cache_hit_rate_7d = multi_day_stats['cache_hit_rate']
        hourly_stats_7d = multi_day_stats['hourly_stats']
        
        # 获取24小时的查询总数
        h24_total_queries = stats_24h['total_queries']
        
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
        
        .ai-analysis {{
            background: linear-gradient(135deg, #ff9a9e 0%, #fecfef 50%, #fecfef 100%);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 30px;
            color: #333;
            box-shadow: 0 15px 35px rgba(255, 154, 158, 0.3);
        }}
        
        .ai-analysis h2 {{
            color: #d63384;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .ai-analysis .content {{
            background: rgba(255, 255, 255, 0.8);
            border-radius: 10px;
            padding: 20px;
            line-height: 1.6;
        }}
        
        .ai-analysis .content h1, .ai-analysis .content h2, .ai-analysis .content h3, .ai-analysis .content h4 {{
            color: #d63384;
            margin: 15px 0 10px 0;
            font-weight: bold;
        }}
        
        .ai-analysis .content h1 {{ font-size: 1.4em; }}
        .ai-analysis .content h2 {{ font-size: 1.3em; }}
        .ai-analysis .content h3 {{ font-size: 1.2em; }}
        .ai-analysis .content h4 {{ font-size: 1.1em; }}
        
        .ai-analysis .content p {{
            margin: 10px 0;
            text-align: justify;
        }}
        
        .ai-analysis .content ul, .ai-analysis .content ol {{
            margin: 10px 0;
            padding-left: 20px;
        }}
        
        .ai-analysis .content li {{
            margin: 5px 0;
            list-style-type: disc;
        }}
        
        .ai-analysis .content ol li {{
            list-style-type: decimal;
        }}
        
        .ai-analysis .content strong {{
            color: #d63384;
            font-weight: bold;
        }}
        
        .ai-analysis .content em {{
            font-style: italic;
            color: #666;
        }}
        
        .ai-analysis .content code {{
            background: rgba(233, 236, 239, 0.8);
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            color: #e83e8c;
        }}
        
        .ai-analysis .content pre {{
            background: rgba(233, 236, 239, 0.8);
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
            overflow-x: auto;
        }}
        
        .ai-analysis .content pre code {{
            background: none;
            padding: 0;
            font-size: 0.9em;
            color: #333;
        }}
        
        .ai-analysis .no-analysis {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-style: italic;
        }}
        
        .ai-analysis .error {{
            background: rgba(220, 53, 69, 0.1);
            border: 1px solid rgba(220, 53, 69, 0.3);
            color: #721c24;
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
        
        <!-- AI态势感知分析 -->
        <div class="ai-analysis">
            <h2>🤖 AI态势感知分析</h2>"""

        if ai_analysis_result['status'] == 'success':
            # 处理纯文本格式的AI分析结果
            analysis_text = ai_analysis_result['analysis'].replace('\n', '<br>')
            html_content += f"""
            <div class="content"><p>{analysis_text}</p></div>"""
        elif ai_analysis_result['status'] == 'no_api_key':
            html_content += f"""
            <div class="no-analysis">
                💡 未配置DeepSeek API密钥，无法进行AI分析<br>
                运行 <code>python3 dnsmasq_analyzer.py --setup-ai</code> 进行配置
            </div>"""
        else:
            html_content += f"""
            <div class="content error">
                ⚠️ AI分析暂时不可用: {ai_analysis_result.get('message', '未知错误')}<br>
                请检查网络连接和API配置
            </div>"""
        
        html_content += f"""
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>24小时查询总数</h3>
                <div class="value">{h24_total_queries:,}</div>
            </div>
            <div class="stat-card">
                <h3>24小时缓存命中率</h3>
                <div class="value">{cache_hit_rate:.1f}%</div>
                <div class="change">命中:{stats_24h['cache_hits']:,} / 未中:{stats_24h['cache_misses']:,}</div>
            </div>
            <div class="stat-card">
                <h3>独立域名数</h3>
                <div class="value">{len(top_domains_24h):,}</div>
            </div>
            <div class="stat-card">
                <h3>活跃客户端</h3>
                <div class="value">{len(top_clients_with_domains):,}</div>
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
        
        html_content += ("""
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
                        <h4>7天总查询</h4>
                        <div class="value">{}</div>
                    </div>
                    <div class="info-item">
                        <h4>最活跃客户端</h4>
                        <div class="value">{}</div>
                    </div>
                </div>
            </div>
        </div>
        """).format(
            f"{max(hourly_stats_7d, key=hourly_stats_7d.get, default=0):02d}:00" if hourly_stats_7d else "N/A",
            f"{total_queries_7d // 24:,}" if total_queries_7d else "0",
            f"{total_queries_7d:,}" if total_queries_7d else "0",
            top_clients_with_domains[0]['client_ip'] if top_clients_with_domains else "N/A"
        )
        
        # TOP 6 客户端及其高频域名
        html_content += """
        <div class="card" style="grid-column: 1 / -1;">
            <h2>🔥 查询量最高的6个客户端及其TOP 10域名</h2>
            <div class="main-content" style="grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));">
"""
        
        # 添加每个客户端的卡片
        for idx, client_data in enumerate(top_clients_with_domains, 1):
            client_ip = client_data['client_ip']
            total_queries = client_data['total_queries']
            top_domains = client_data['top_domains']
            
            html_content += f"""
                <div class="card" style="margin: 0;">
                    <h3 style="color: #667eea; margin-bottom: 15px; display: flex; align-items: center; gap: 10px;">
                        <span class="domain-rank" style="font-size: 14px;">{idx}</span>
                        {client_ip}
                        <span style="font-size: 14px; color: #666; font-weight: normal;">({total_queries:,} 次查询)</span>
                    </h3>
                    <div class="domain-list" style="max-height: 350px;">
"""
            
            # 添加该客户端的TOP域名
            for domain_idx, (domain, count) in enumerate(top_domains, 1):
                percentage = (count / total_queries * 100) if total_queries > 0 else 0
                html_content += f"""
                        <div class="domain-item">
                            <span class="domain-rank" style="width: 25px; height: 25px; line-height: 25px; font-size: 12px;">{domain_idx}</span>
                            <span class="domain-name" style="font-size: 14px;">{domain}</span>
                            <div style="display: flex; flex-direction: column; align-items: flex-end;">
                                <span class="domain-count" style="background: #28a745;">{count:,}</span>
                                <small style="color: #666; font-size: 11px; margin-top: 2px;">{percentage:.1f}%</small>
                            </div>
                        </div>
"""
            
            html_content += """
                    </div>
                </div>
"""
        
        html_content += """
            </div>
        </div>
        
        <div class="card" style="grid-column: 1 / -1;">
            <h2>💾 缓存性能分析</h2>
            <div class="main-content">
                <div>
                    <h3 style="color: #666; margin-bottom: 15px;">🔥 缓存命中最多的域名 TOP 10</h3>
                    <div class="domain-list" style="max-height: 300px;">
"""
        
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
        for server, count in upstream_servers[:5]:
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
        
        for idx, (domain, count) in enumerate(all_time_domains, 1):
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
    parser.add_argument('--setup-ai', action='store_true',
                       help='配置DeepSeek AI分析功能')
    parser.add_argument('--api-key', type=str,
                       help='直接设置DeepSeek API密钥')
    parser.add_argument('--test-ai', action='store_true',
                       help='测试DeepSeek AI连接')
    
    args = parser.parse_args()
    
    print("=" * 50)
    print("DNSmasq 日志分析工具")
    print("=" * 50)
    
    analyzer = DnsmasqAnalyzer(log_file=args.log, data_dir=args.data_dir, keep_days=args.keep_days, exclude_arpa=not args.include_arpa)
    
    # 命令行直接设置API密钥
    if args.api_key:
        print("\n正在设置DeepSeek API密钥...")
        if analyzer.setup_deepseek_config(api_key=args.api_key):
            print("✅ API密钥设置成功!")
        else:
            print("❌ API密钥设置失败!")
        return
    
    # AI配置模式（交互式）
    if args.setup_ai:
        print("\n正在配置DeepSeek AI分析功能...")
        if analyzer.setup_deepseek_config():
            print("✅ AI功能配置完成!")
        else:
            print("❌ AI功能配置失败!")
        return
    
    # AI测试模式
    if args.test_ai:
        print("\n正在测试DeepSeek AI连接...")
        if not analyzer.deepseek_api_key:
            print("❌ 未配置API密钥，请先运行 --setup-ai 进行配置")
            return
        
        test_prompt = "请简单介绍一下DNS协议的作用，用一句话回答。"
        result = analyzer.call_deepseek_api(test_prompt, max_tokens=100)
        
        if result:
            print("✅ DeepSeek API连接成功!")
            print(f"测试响应: {result}")
        else:
            print("❌ DeepSeek API连接失败，请检查API密钥和网络连接")
        return
    
    # 如果只是清理模式
    if args.cleanup_only:
        print(f"\n正在清理超过 {args.keep_days} 天的数据文件...")
        analyzer.cleanup_old_data()
        # 显示数据库大小
        db_size = analyzer.db_file.stat().st_size / 1024 / 1024 if analyzer.db_file.exists() else 0
        print(f"清理完成，当前数据库大小: {db_size:.2f} MB")
        return
    
    # 分析日志
    print("\n正在分析日志文件...")
    if analyzer.analyze_log():
        # 生成报告
        print("\n正在生成HTML报告...")
        analyzer.generate_html_report(output_file=args.output)
        
        print("\n✅ 分析完成!")
        # 获取今天的统计数据
        today_stats = analyzer.get_statistics_from_db()
        print(f"📊 共分析 {today_stats['total_queries']} 条查询记录")
        print(f"📁 数据库保存在: {analyzer.db_file}")
        print(f"📄 HTML报告: {args.output}")
        
        # AI功能状态提示
        if analyzer.deepseek_api_key:
            print("🤖 AI态势感知分析已集成到HTML报告中")
        else:
            print("💡 未配置AI功能，运行 'python3 dnsmasq_analyzer.py --setup-ai' 启用智能分析")
    else:
        print("\n❌ 分析失败，请检查日志文件是否存在且有读取权限")
        sys.exit(1)

if __name__ == "__main__":
    main()