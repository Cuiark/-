import re
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
import argparse
import os
import datetime
import ipaddress
from collections import Counter, defaultdict
import json
from pathlib import Path
import fnmatch

# 设置中文字体支持
try:
    plt.rcParams['font.sans-serif'] = ['SimHei']  # 用来正常显示中文标签
    plt.rcParams['axes.unicode_minus'] = False    # 用来正常显示负号
except:
    print("警告: 无法设置中文字体，图表中的中文可能无法正确显示")

# 日志解析正则表达式列表
LOG_PATTERNS = {
    's': r'^(\S+) - - \[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "(.*)" "(.*)" "(.*)"',
    'n': r'^(\S+) - - \[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "\s*(.*)\s*" "(.*)"$',
    'a': r'^(\S+) - - \[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d+) (\d+)'
}

class LogAnalyzer:
    def __init__(self, log_file=None, log_dir=None, output_dir="./output", swagger_patterns_file="swagger_patterns.json", pattern_type="s"):
        self.log_file = log_file
        self.log_dir = log_dir
        self.pattern_type = pattern_type
        self.log_pattern = LOG_PATTERNS.get(pattern_type, LOG_PATTERNS['s'])
        
        # 处理输出目录路径
        self.output_dir = os.path.abspath(output_dir) if os.path.isabs(output_dir) else os.path.abspath(output_dir)
        self.logs = []
        self.df = None
        self.swagger_patterns_file = swagger_patterns_file
        self.swagger_patterns = self.load_swagger_patterns()
        
        # 创建输出目录
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def load_swagger_patterns(self):
        """加载Swagger模式字典"""
        try:
            with open(self.swagger_patterns_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"警告: 无法加载Swagger模式字典文件: {e}")
            # 返回默认的简单模式
            return {
                "swagger_paths": ["/swagger", "/swagger-ui.html", "/api-docs", "/v2/api-docs"],
                "swagger_keywords": ["swagger", "api-docs"],
                "swagger_file_extensions": [".json", ".yaml"],
                "swagger_parameters": ["swagger="]
            }
    
    def parse_log_file(self, file_path):
        """解析单个日志文件"""
        parsed_logs = []
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                try:
                    match = re.match(self.log_pattern, line.strip())
                    if match:
                        groups = match.groups()
                        
                        # 根据匹配的组数决定如何解析
                        if len(groups) >= 10:  # s格式(standard)
                            ip, timestamp, method, path, protocol, status, size, referer, user_agent, extra = groups[:10]
                        elif len(groups) >= 8:  # n格式(nginx)
                            ip, timestamp, method, path, protocol, status, size, referer, user_agent = groups[:9]
                            extra = ""
                        elif len(groups) >= 6:  # a格式(apache)
                            ip, timestamp, method, path, protocol, status, size = groups[:7]
                            referer = user_agent = extra = ""
                        else:
                            continue
                        
                        # 解析时间戳
                        dt = datetime.datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z")
                        
                        parsed_logs.append({
                            'ip': ip,
                            'timestamp': dt,
                            'date': dt.date(),
                            'time': dt.time(),
                            'method': method,
                            'path': path,
                            'protocol': protocol,
                            'status': int(status),
                            'size': int(size),
                            'referer': referer.strip(),
                            'user_agent': user_agent,
                            'extra': extra
                        })
                except Exception as e:
                    print(f"解析行时出错: {line}\n错误: {e}")
        return parsed_logs
    
    def load_logs(self):
        """加载日志文件"""
        if self.log_file:
            self.logs = self.parse_log_file(self.log_file)
        elif self.log_dir:
            for file in os.listdir(self.log_dir):
                if file.endswith('.log') or file.endswith('.txt'):
                    file_path = os.path.join(self.log_dir, file)
                    self.logs.extend(self.parse_log_file(file_path))
        
        if self.logs:
            self.df = pd.DataFrame(self.logs)
            print(f"成功加载 {len(self.logs)} 条日志记录")
        else:
            print("未找到任何日志记录")
    
    def basic_stats(self):
        """生成基本统计信息"""
        if self.df is None or self.df.empty:
            print("没有日志数据可分析")
            return {}
        
        stats = {
            "总请求数": len(self.df),
            "唯一IP数": self.df['ip'].nunique(),
            "请求方法分布": self.df['method'].value_counts().to_dict(),
            "状态码分布": self.df['status'].value_counts().to_dict(),
            "平均响应大小": self.df['size'].mean(),
            "最大响应大小": self.df['size'].max(),
            "最小响应大小": self.df['size'].min(),
            "时间范围": {
                "开始": self.df['timestamp'].min().strftime("%Y-%m-%d %H:%M:%S"),
                "结束": self.df['timestamp'].max().strftime("%Y-%m-%d %H:%M:%S")
            },
            "热门请求路径": self.df['path'].value_counts().head(10).to_dict()
        }
        
        return stats
    
    def analyze_traffic_by_time(self):
        """按时间分析流量"""
        if self.df is None or self.df.empty:
            return
        
        # 按小时统计请求数
        self.df['hour'] = self.df['timestamp'].dt.hour
        hourly_traffic = self.df.groupby('hour').size()
        
        plt.figure(figsize=(12, 6))
        hourly_traffic.plot(kind='bar', color='skyblue')
        plt.title('每小时请求数')
        plt.xlabel('小时')
        plt.ylabel('请求数')
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'hourly_traffic.png'))
        plt.close()
        
        # 按日期统计请求数
        self.df['date_only'] = self.df['timestamp'].dt.date
        daily_traffic = self.df.groupby('date_only').size()
        
        plt.figure(figsize=(12, 6))
        daily_traffic.plot(kind='line', marker='o', color='green')
        plt.title('每日请求数')
        plt.xlabel('日期')
        plt.ylabel('请求数')
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'daily_traffic.png'))
        plt.close()
    
    def analyze_status_codes(self):
        """分析状态码"""
        if self.df is None or self.df.empty:
            return
        
        status_counts = self.df['status'].value_counts()
        
        plt.figure(figsize=(10, 6))
        status_counts.plot(kind='pie', autopct='%1.1f%%', startangle=90, colors=plt.cm.Paired.colors)
        plt.title('HTTP状态码分布')
        plt.ylabel('')
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'status_codes.png'))
        plt.close()
        
        # 按时间分析错误状态码
        error_df = self.df[self.df['status'] >= 400]
        if not error_df.empty:
            error_df['hour'] = error_df['timestamp'].dt.hour
            hourly_errors = error_df.groupby(['hour', 'status']).size().unstack(fill_value=0)
            
            plt.figure(figsize=(12, 6))
            hourly_errors.plot(kind='bar', stacked=True)
            plt.title('每小时错误状态码分布')
            plt.xlabel('小时')
            plt.ylabel('错误数')
            plt.grid(axis='y', linestyle='--', alpha=0.7)
            plt.legend(title='状态码')
            plt.tight_layout()
            plt.savefig(os.path.join(self.output_dir, 'hourly_errors.png'))
            plt.close()
    
    def analyze_ip_addresses(self):
        """分析IP地址"""
        if self.df is None or self.df.empty:
            return
        
        # 获取访问频率最高的IP
        top_ips = self.df['ip'].value_counts().head(10)
        
        plt.figure(figsize=(12, 6))
        top_ips.plot(kind='bar', color='orange')
        plt.title('访问频率最高的IP地址')
        plt.xlabel('IP地址')
        plt.ylabel('请求数')
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'top_ips.png'))
        plt.close()
        
        # 尝试分析IP地址的地理分布（简化版，只按网段分类）
        ip_segments = []
        for ip in self.df['ip']:
            try:
                # 提取IP的前两段作为网段标识
                segments = ip.split('.')
                if len(segments) >= 2:
                    ip_segments.append(f"{segments[0]}.{segments[1]}")
            except:
                continue
        
        segment_counts = Counter(ip_segments)
        top_segments = dict(segment_counts.most_common(10))
        
        plt.figure(figsize=(12, 6))
        plt.bar(top_segments.keys(), top_segments.values(), color='purple')
        plt.title('访问频率最高的IP网段')
        plt.xlabel('IP网段')
        plt.ylabel('请求数')
        plt.xticks(rotation=45)
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'top_ip_segments.png'))
        plt.close()
    
    def analyze_request_methods(self):
        """分析请求方法"""
        if self.df is None or self.df.empty:
            return
        
        method_counts = self.df['method'].value_counts()
        
        plt.figure(figsize=(10, 6))
        method_counts.plot(kind='bar', color='teal')
        plt.title('HTTP请求方法分布')
        plt.xlabel('请求方法')
        plt.ylabel('请求数')
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'request_methods.png'))
        plt.close()
    
    def analyze_endpoints(self):
        """分析请求的端点"""
        if self.df is None or self.df.empty:
            return
        
        # 获取访问频率最高的端点
        top_paths = self.df['path'].value_counts().head(10)
        
        plt.figure(figsize=(14, 6))
        top_paths.plot(kind='barh', color='darkgreen')
        plt.title('访问频率最高的端点')
        plt.xlabel('请求数')
        plt.ylabel('端点路径')
        plt.grid(axis='x', linestyle='--', alpha=0.7)
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'top_endpoints.png'))
        plt.close()
        
        # 分析每个端点的状态码分布
        path_status = self.df.groupby(['path', 'status']).size().unstack(fill_value=0)
        top_paths_data = path_status.loc[top_paths.index[:5]]
        
        plt.figure(figsize=(14, 8))
        top_paths_data.plot(kind='bar', stacked=True)
        plt.title('热门端点的状态码分布')
        plt.xlabel('端点路径')
        plt.ylabel('请求数')
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        plt.legend(title='状态码')
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'endpoint_status_codes.png'))
        plt.close()
    
    def search_swagger_patterns(self):
        """使用字典搜索流量中是否存在Swagger相关的请求路径或特征"""
        if self.df is None or self.df.empty:
            return {}
        
        swagger_results = {
            "swagger_paths": [],
            "swagger_requests": []
        }
        
        # 获取所有Swagger模式
        swagger_paths = self.swagger_patterns.get("swagger_paths", [])
        swagger_keywords = self.swagger_patterns.get("swagger_keywords", [])
        swagger_file_extensions = self.swagger_patterns.get("swagger_file_extensions", [])
        swagger_parameters = self.swagger_patterns.get("swagger_parameters", [])
        
        # 搜索精确匹配的路径
        for path in swagger_paths:
            matches = self.df[self.df['path'] == path]
            if not matches.empty:
                for _, row in matches.iterrows():
                    swagger_results["swagger_paths"].append(path)
                    swagger_results["swagger_requests"].append({
                        "timestamp": row['timestamp'],
                        "ip": row['ip'],
                        "method": row['method'],
                        "path": row['path'],
                        "status": row['status'],
                        "match_type": "精确路径匹配"
                    })
        
        # 搜索包含关键词的路径
        for keyword in swagger_keywords:
            for _, row in self.df.iterrows():
                if keyword.lower() in row['path'].lower():
                    if row['path'] not in swagger_results["swagger_paths"]:
                        swagger_results["swagger_paths"].append(row['path'])
                        swagger_results["swagger_requests"].append({
                            "timestamp": row['timestamp'],
                            "ip": row['ip'],
                            "method": row['method'],
                            "path": row['path'],
                            "status": row['status'],
                            "match_type": f"关键词匹配: {keyword}"
                        })
        
        # 搜索特定文件扩展名
        for ext in swagger_file_extensions:
            for _, row in self.df.iterrows():
                if row['path'].lower().endswith(ext):
                    # 检查是否包含swagger关键词，以减少误报
                    has_keyword = False
                    for keyword in swagger_keywords:
                        if keyword.lower() in row['path'].lower():
                            has_keyword = True
                            break
                    
                    if has_keyword and row['path'] not in swagger_results["swagger_paths"]:
                        swagger_results["swagger_paths"].append(row['path'])
                        swagger_results["swagger_requests"].append({
                            "timestamp": row['timestamp'],
                            "ip": row['ip'],
                            "method": row['method'],
                            "path": row['path'],
                            "status": row['status'],
                            "match_type": f"文件扩展名匹配: {ext}"
                        })
        
        # 搜索包含特定参数的请求
        for param in swagger_parameters:
            for _, row in self.df.iterrows():
                if param in row['path'] and row['path'] not in swagger_results["swagger_paths"]:
                    swagger_results["swagger_paths"].append(row['path'])
                    swagger_results["swagger_requests"].append({
                        "timestamp": row['timestamp'],
                        "ip": row['ip'],
                        "method": row['method'],
                        "path": row['path'],
                        "status": row['status'],
                        "match_type": f"参数匹配: {param}"
                    })
        
        # 使用通配符模式匹配
        wildcard_patterns = [
            "*/swagger*",
            "*/api-docs*",
            "*/openapi*",
            "*/swagger*/ui*",
            "*/v*/api-docs*"
        ]
        
        for pattern in wildcard_patterns:
            for _, row in self.df.iterrows():
                if fnmatch.fnmatch(row['path'].lower(), pattern) and row['path'] not in swagger_results["swagger_paths"]:
                    swagger_results["swagger_paths"].append(row['path'])
                    swagger_results["swagger_requests"].append({
                        "timestamp": row['timestamp'],
                        "ip": row['ip'],
                        "method": row['method'],
                        "path": row['path'],
                        "status": row['status'],
                        "match_type": f"通配符匹配: {pattern}"
                    })
        
        return swagger_results
    
    def analyze_suspicious_urls(self):
        """分析可疑的URL模式"""
        if self.df is None or self.df.empty:
            return {}
        
        suspicious_results = {
            "path_traversal_attacks": [],
            "admin_access_attempts": [],
            "system_file_access": [],
            "sql_injection_attempts": [],
            "xss_attempts": [],
            "other_suspicious": []
        }
        
        # 定义可疑URL模式
        patterns = {
            "path_traversal": [
                "../", "..%2f", "..%5c", "%2e%2e%2f", "%2e%2e%5c",
                "....//", "....\\\\" 
            ],
            "admin_paths": [
                "/admin", "/administrator", "/wp-admin", "/phpmyadmin",
                "/cpanel", "/webmail", "/manager", "/console",
                "/dashboard", "/control", "/panel", "/backend"
            ],
            "system_files": [
                "/etc/passwd", "/etc/shadow", "/windows/system32",
                "/boot.ini", "/web.config", "/config.php",
                "/wp-config.php", "/database.yml", "/.env",
                "/proc/", "/sys/", "/dev/"
            ],
            "sql_injection": [
                "union select", "' or 1=1", "' or '1'='1",
                "drop table", "insert into", "delete from",
                "exec(", "execute(", "sp_", "xp_"
            ],
            "xss_patterns": [
                "<script", "javascript:", "onload=", "onerror=",
                "alert(", "document.cookie", "<iframe", "<object"
            ],
            "other_suspicious": [
                "shell", "cmd", "command", "eval", "exec",
                "system", "passthru", "file_get_contents",
                "include", "require", "phpinfo"
            ]
        }
        
        # 检查每个请求的路径
        for _, row in self.df.iterrows():
            path = row['path'].lower()
            
            # 检测路径遍历攻击
            for pattern in patterns["path_traversal"]:
                if pattern in path:
                    suspicious_results["path_traversal_attacks"].append({
                        "timestamp": row['timestamp'],
                        "ip": row['ip'],
                        "method": row['method'],
                        "path": row['path'],
                        "status": row['status'],
                        "pattern": pattern,
                        "risk_level": "高"
                    })
                    break
            
            # 检测管理员路径访问
            for pattern in patterns["admin_paths"]:
                if pattern in path:
                    suspicious_results["admin_access_attempts"].append({
                        "timestamp": row['timestamp'],
                        "ip": row['ip'],
                        "method": row['method'],
                        "path": row['path'],
                        "status": row['status'],
                        "pattern": pattern,
                        "risk_level": "中"
                    })
                    break
            
            # 检测系统文件访问
            for pattern in patterns["system_files"]:
                if pattern in path:
                    suspicious_results["system_file_access"].append({
                        "timestamp": row['timestamp'],
                        "ip": row['ip'],
                        "method": row['method'],
                        "path": row['path'],
                        "status": row['status'],
                        "pattern": pattern,
                        "risk_level": "高"
                    })
                    break
            
            # 检测SQL注入尝试
            for pattern in patterns["sql_injection"]:
                if pattern in path:
                    suspicious_results["sql_injection_attempts"].append({
                        "timestamp": row['timestamp'],
                        "ip": row['ip'],
                        "method": row['method'],
                        "path": row['path'],
                        "status": row['status'],
                        "pattern": pattern,
                        "risk_level": "高"
                    })
                    break
            
            # 检测XSS尝试
            for pattern in patterns["xss_patterns"]:
                if pattern in path:
                    suspicious_results["xss_attempts"].append({
                        "timestamp": row['timestamp'],
                        "ip": row['ip'],
                        "method": row['method'],
                        "path": row['path'],
                        "status": row['status'],
                        "pattern": pattern,
                        "risk_level": "中"
                    })
                    break
            
            # 检测其他可疑模式
            for pattern in patterns["other_suspicious"]:
                if pattern in path:
                    suspicious_results["other_suspicious"].append({
                        "timestamp": row['timestamp'],
                        "ip": row['ip'],
                        "method": row['method'],
                        "path": row['path'],
                        "status": row['status'],
                        "pattern": pattern,
                        "risk_level": "中"
                    })
                    break
        
        return suspicious_results
    
    def detect_anomalies(self):
        """检测异常情况"""
        if self.df is None or self.df.empty:
            return {}
        
        anomalies = {}
        
        # 检测可能的扫描行为（短时间内大量不同路径请求）
        ip_path_counts = self.df.groupby('ip')['path'].nunique()
        potential_scanners = ip_path_counts[ip_path_counts > 20].to_dict()
        if potential_scanners:
            anomalies["可能的扫描行为"] = potential_scanners
        
        # 检测大量错误请求
        error_counts = self.df[self.df['status'] >= 400].groupby('ip').size()
        high_error_ips = error_counts[error_counts > 10].to_dict()
        if high_error_ips:
            anomalies["大量错误请求的IP"] = high_error_ips
        
        # 检测异常大小的响应
        size_mean = self.df['size'].mean()
        size_std = self.df['size'].std()
        large_responses = self.df[self.df['size'] > (size_mean + 3*size_std)]
        if not large_responses.empty:
            anomalies["异常大小的响应"] = large_responses[['timestamp', 'ip', 'path', 'size']].to_dict('records')
        
        # 检测Swagger相关请求
        swagger_results = self.search_swagger_patterns()
        if swagger_results["swagger_requests"]:
            anomalies["Swagger相关请求"] = swagger_results["swagger_requests"]
        
        # 检测可疑URL模式
        suspicious_urls = self.analyze_suspicious_urls()
        if any(suspicious_urls.values()):
            anomalies["可疑URL访问"] = suspicious_urls
        
        return anomalies
    
    def generate_report(self):
        """生成分析报告"""
        if self.df is None or self.df.empty:
            print("没有日志数据可分析")
            return
        
        # 运行所有分析
        stats = self.basic_stats()
        anomalies = self.detect_anomalies()
        
        self.analyze_traffic_by_time()
        self.analyze_status_codes()
        self.analyze_ip_addresses()
        self.analyze_request_methods()
        self.analyze_endpoints()
        
        # 生成HTML报告
        report_path = os.path.join(self.output_dir, 'report.html')
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(f'''
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>日志分析报告</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1, h2, h3 {{ color: #333; }}
                    .container {{ max-width: 1200px; margin: 0 auto; }}
                    .stats {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                    .chart {{ margin: 20px 0; text-align: center; }}
                    .chart img {{ max-width: 100%; border: 1px solid #ddd; border-radius: 5px; }}
                    table {{ border-collapse: collapse; width: 100%; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                    tr:nth-child(even) {{ background-color: #f9f9f9; }}
                    .anomaly {{ background-color: #fff0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; border-left: 4px solid #ff6b6b; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>日志分析报告</h1>
                    <p>生成时间: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                    
                    <h2>基本统计信息</h2>
                    <div class="stats">
                        <p>总请求数: {stats.get("总请求数", 0)}</p>
                        <p>唯一IP数: {stats.get("唯一IP数", 0)}</p>
                        <p>时间范围: {stats.get("时间范围", {}).get("开始", "N/A")} 至 {stats.get("时间范围", {}).get("结束", "N/A")}</p>
                        <p>平均响应大小: {stats.get("平均响应大小", 0):.2f} 字节</p>
                    </div>
                    
                    <h2>请求方法分布</h2>
                    <table>
                        <tr>
                            <th>方法</th>
                            <th>请求数</th>
                        </tr>
                        {''.join([f"<tr><td>{method}</td><td>{count}</td></tr>" for method, count in stats.get("请求方法分布", {}).items()])}
                    </table>
                    
                    <h2>状态码分布</h2>
                    <table>
                        <tr>
                            <th>状态码</th>
                            <th>请求数</th>
                        </tr>
                        {''.join([f"<tr><td>{status}</td><td>{count}</td></tr>" for status, count in stats.get("状态码分布", {}).items()])}
                    </table>
                    
                    <h2>热门请求路径</h2>
                    <table>
                        <tr>
                            <th>路径</th>
                            <th>请求数</th>
                        </tr>
                        {''.join([f"<tr><td>{path}</td><td>{count}</td></tr>" for path, count in stats.get("热门请求路径", {}).items()])}
                    </table>
                    
                    <h2>流量分析图表</h2>
                    
                    <div class="chart">
                        <h3>每小时请求数</h3>
                        <img src="hourly_traffic.png" alt="每小时请求数">
                    </div>
                    
                    <div class="chart">
                        <h3>每日请求数</h3>
                        <img src="daily_traffic.png" alt="每日请求数">
                    </div>
                    
                    <div class="chart">
                        <h3>HTTP状态码分布</h3>
                        <img src="status_codes.png" alt="HTTP状态码分布">
                    </div>
                    
                    <div class="chart">
                        <h3>访问频率最高的IP地址</h3>
                        <img src="top_ips.png" alt="访问频率最高的IP地址">
                    </div>
                    
                    <div class="chart">
                        <h3>访问频率最高的IP网段</h3>
                        <img src="top_ip_segments.png" alt="访问频率最高的IP网段">
                    </div>
                    
                    <div class="chart">
                        <h3>HTTP请求方法分布</h3>
                        <img src="request_methods.png" alt="HTTP请求方法分布">
                    </div>
                    
                    <div class="chart">
                        <h3>访问频率最高的端点</h3>
                        <img src="top_endpoints.png" alt="访问频率最高的端点">
                    </div>
                    
                    <div class="chart">
                        <h3>热门端点的状态码分布</h3>
                        <img src="endpoint_status_codes.png" alt="热门端点的状态码分布">
                    </div>
            ''')
            
            # 添加异常检测部分
            if anomalies:
                f.write('''
                    <h2>异常检测</h2>
                ''')
                
                if "可能的扫描行为" in anomalies:
                    f.write('''
                    <div class="anomaly">
                        <h3>可能的扫描行为</h3>
                        <p>以下IP地址在短时间内请求了大量不同的路径，可能是扫描行为：</p>
                        <table>
                            <tr>
                                <th>IP地址</th>
                                <th>不同路径数</th>
                            </tr>
                    ''')
                    for ip, path_count in anomalies["可能的扫描行为"].items():
                        f.write(f"<tr><td>{ip}</td><td>{path_count}</td></tr>")
                    f.write("</table></div>")
                
                if "大量错误请求的IP" in anomalies:
                    f.write('''
                    <div class="anomaly">
                        <h3>大量错误请求的IP</h3>
                        <p>以下IP地址产生了大量错误请求：</p>
                        <table>
                            <tr>
                                <th>IP地址</th>
                                <th>错误请求数</th>
                            </tr>
                    ''')
                    for ip, error_count in anomalies["大量错误请求的IP"].items():
                        f.write(f"<tr><td>{ip}</td><td>{error_count}</td></tr>")
                    f.write("</table></div>")
                
                if "异常大小的响应" in anomalies:
                    f.write('''
                    <div class="anomaly">
                        <h3>异常大小的响应</h3>
                        <p>以下请求产生了异常大小的响应：</p>
                        <table>
                            <tr>
                                <th>时间</th>
                                <th>IP地址</th>
                                <th>路径</th>
                                <th>响应大小</th>
                            </tr>
                    ''')
                    for resp in anomalies["异常大小的响应"]:
                        f.write(f"<tr><td>{resp['timestamp']}</td><td>{resp['ip']}</td><td>{resp['path']}</td><td>{resp['size']}</td></tr>")
                    f.write("</table></div>")
                
                if "Swagger相关请求" in anomalies:
                    f.write('''
                    <div class="anomaly">
                        <h3>Swagger API文档相关请求</h3>
                        <p>检测到以下可能与Swagger API文档相关的请求，这可能表明API文档暴露在公网：</p>
                        <table>
                            <tr>
                                <th>时间</th>
                                <th>IP地址</th>
                                <th>方法</th>
                                <th>路径</th>
                                <th>状态码</th>
                                <th>匹配类型</th>
                            </tr>
                    ''')
                    for req in anomalies["Swagger相关请求"]:
                        f.write(f"<tr><td>{req['timestamp']}</td><td>{req['ip']}</td><td>{req['method']}</td><td>{req['path']}</td><td>{req['status']}</td><td>{req['match_type']}</td></tr>")
                    f.write("</table></div>")
                
                if "可疑URL访问" in anomalies:
                    suspicious_urls = anomalies["可疑URL访问"]
                    
                    # 路径遍历攻击
                    if suspicious_urls.get("path_traversal_attacks"):
                        f.write('''
                        <div class="anomaly">
                            <h3>路径遍历攻击检测</h3>
                            <p>检测到以下可能的路径遍历攻击尝试（../../../等模式）：</p>
                            <table>
                                <tr>
                                    <th>时间</th>
                                    <th>IP地址</th>
                                    <th>方法</th>
                                    <th>路径</th>
                                    <th>状态码</th>
                                    <th>匹配模式</th>
                                    <th>风险等级</th>
                                </tr>
                        ''')
                        for req in suspicious_urls["path_traversal_attacks"]:
                            f.write(f"<tr><td>{req['timestamp']}</td><td>{req['ip']}</td><td>{req['method']}</td><td>{req['path']}</td><td>{req['status']}</td><td>{req['pattern']}</td><td>{req['risk_level']}</td></tr>")
                        f.write("</table></div>")
                    
                    # 管理员路径访问
                    if suspicious_urls.get("admin_access_attempts"):
                        f.write('''
                        <div class="anomaly">
                            <h3>管理员路径访问尝试</h3>
                            <p>检测到以下对管理员路径的访问尝试：</p>
                            <table>
                                <tr>
                                    <th>时间</th>
                                    <th>IP地址</th>
                                    <th>方法</th>
                                    <th>路径</th>
                                    <th>状态码</th>
                                    <th>匹配模式</th>
                                    <th>风险等级</th>
                                </tr>
                        ''')
                        for req in suspicious_urls["admin_access_attempts"]:
                            f.write(f"<tr><td>{req['timestamp']}</td><td>{req['ip']}</td><td>{req['method']}</td><td>{req['path']}</td><td>{req['status']}</td><td>{req['pattern']}</td><td>{req['risk_level']}</td></tr>")
                        f.write("</table></div>")
                    
                    # 系统文件访问
                    if suspicious_urls.get("system_file_access"):
                        f.write('''
                        <div class="anomaly">
                            <h3>系统文件访问尝试</h3>
                            <p>检测到以下对系统文件的访问尝试：</p>
                            <table>
                                <tr>
                                    <th>时间</th>
                                    <th>IP地址</th>
                                    <th>方法</th>
                                    <th>路径</th>
                                    <th>状态码</th>
                                    <th>匹配模式</th>
                                    <th>风险等级</th>
                                </tr>
                        ''')
                        for req in suspicious_urls["system_file_access"]:
                            f.write(f"<tr><td>{req['timestamp']}</td><td>{req['ip']}</td><td>{req['method']}</td><td>{req['path']}</td><td>{req['status']}</td><td>{req['pattern']}</td><td>{req['risk_level']}</td></tr>")
                        f.write("</table></div>")
                    
                    # SQL注入尝试
                    if suspicious_urls.get("sql_injection_attempts"):
                        f.write('''
                        <div class="anomaly">
                            <h3>SQL注入攻击尝试</h3>
                            <p>检测到以下可能的SQL注入攻击尝试：</p>
                            <table>
                                <tr>
                                    <th>时间</th>
                                    <th>IP地址</th>
                                    <th>方法</th>
                                    <th>路径</th>
                                    <th>状态码</th>
                                    <th>匹配模式</th>
                                    <th>风险等级</th>
                                </tr>
                        ''')
                        for req in suspicious_urls["sql_injection_attempts"]:
                            f.write(f"<tr><td>{req['timestamp']}</td><td>{req['ip']}</td><td>{req['method']}</td><td>{req['path']}</td><td>{req['status']}</td><td>{req['pattern']}</td><td>{req['risk_level']}</td></tr>")
                        f.write("</table></div>")
                    
                    # XSS攻击尝试
                    if suspicious_urls.get("xss_attempts"):
                        f.write('''
                        <div class="anomaly">
                            <h3>XSS攻击尝试</h3>
                            <p>检测到以下可能的跨站脚本攻击尝试：</p>
                            <table>
                                <tr>
                                    <th>时间</th>
                                    <th>IP地址</th>
                                    <th>方法</th>
                                    <th>路径</th>
                                    <th>状态码</th>
                                    <th>匹配模式</th>
                                    <th>风险等级</th>
                                </tr>
                        ''')
                        for req in suspicious_urls["xss_attempts"]:
                            f.write(f"<tr><td>{req['timestamp']}</td><td>{req['ip']}</td><td>{req['method']}</td><td>{req['path']}</td><td>{req['status']}</td><td>{req['pattern']}</td><td>{req['risk_level']}</td></tr>")
                        f.write("</table></div>")
                    
                    # 其他可疑活动
                    if suspicious_urls.get("other_suspicious"):
                        f.write('''
                        <div class="anomaly">
                            <h3>其他可疑活动</h3>
                            <p>检测到以下其他可疑的访问模式：</p>
                            <table>
                                <tr>
                                    <th>时间</th>
                                    <th>IP地址</th>
                                    <th>方法</th>
                                    <th>路径</th>
                                    <th>状态码</th>
                                    <th>匹配模式</th>
                                    <th>风险等级</th>
                                </tr>
                        ''')
                        for req in suspicious_urls["other_suspicious"]:
                            f.write(f"<tr><td>{req['timestamp']}</td><td>{req['ip']}</td><td>{req['method']}</td><td>{req['path']}</td><td>{req['status']}</td><td>{req['pattern']}</td><td>{req['risk_level']}</td></tr>")
                        f.write("</table></div>")
            
            # 结束HTML
            f.write('''
                </div>
            </body>
            </html>
            ''')
        
        # 生成JSON报告
        json_report = {
            "基本统计信息": stats,
            "异常检测": anomalies
        }
        
        with open(os.path.join(self.output_dir, 'report.json'), 'w', encoding='utf-8') as f:
            json.dump(json_report, f, ensure_ascii=False, indent=4, default=str)
        
        # 生成CSV报告
        if not self.df.empty:
            self.df.to_csv(os.path.join(self.output_dir, 'logs.csv'), index=False)
        
        print(f"报告已生成到 {self.output_dir} 目录")
        print(f"HTML报告: {os.path.join(self.output_dir, 'report.html')}")
        print(f"JSON报告: {os.path.join(self.output_dir, 'report.json')}")
        print(f"CSV数据: {os.path.join(self.output_dir, 'logs.csv')}")

def main():
    parser = argparse.ArgumentParser(description='Web服务器日志分析工具')
    parser.add_argument('-f', '--file', help='日志文件路径')
    parser.add_argument('-d', '--directory', help='包含日志文件的目录路径')
    parser.add_argument('-o', '--output', default='./output', help='输出目录路径（支持相对或绝对路径）')
    parser.add_argument('-s', '--swagger', help='Swagger模式字典文件路径', default='swagger_patterns.json')
    parser.add_argument('-p', '--pattern', choices=['s', 'n', 'a'], 
                       default='s', help='日志格式类型 (默认: s)')
    
    args = parser.parse_args()
    
    if not args.file and not args.directory:
        parser.error("请提供日志文件路径(-f)或日志目录路径(-d)")
    
    # 处理输出目录
    output_dir = args.output
    print(f"将分析结果输出到目录: {os.path.abspath(output_dir)}")
    print(f"使用日志格式: {args.pattern}")
    
    analyzer = LogAnalyzer(log_file=args.file, log_dir=args.directory, output_dir=output_dir, 
                          swagger_patterns_file=args.swagger, pattern_type=args.pattern)
    analyzer.load_logs()
    analyzer.generate_report()

if __name__ == "__main__":
    main()