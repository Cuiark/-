import re
import argparse
import os
import datetime
import json
import fnmatch
import sys
from collections import Counter, defaultdict

# 日志解析正则表达式列表
LOG_PATTERNS = {
    's': r'^(\S+) - - \[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "(.*)" "(.*)" "(.*)"',
    'n': r'^(\S+) - - \[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "\s*(.*)\s*" "(.*)"$',
    'a': r'^(\S+) - - \[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d+) (\d+)'
}

class LogAnalyzer:
    def __init__(self, log_file, swagger_patterns_file="swagger_patterns.json", output_path=None, pattern_type="s"):
        self.log_file = log_file
        self.pattern_type = pattern_type
        self.log_pattern = LOG_PATTERNS.get(pattern_type, LOG_PATTERNS['s'])
        self.logs = []
        self.ip_counter = Counter()
        self.error_404_counter = Counter()
        self.swagger_counter = Counter()
        self.image_counter = Counter()
        self.swagger_patterns_file = swagger_patterns_file
        self.swagger_patterns = self.load_swagger_patterns()
        self.output_path = output_path
    
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
    
    def parse_log_file(self):
        """解析日志文件"""
        with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
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
                        elif len(groups) >= 6:  # a格式(apache)
                            ip, timestamp, method, path, protocol, status, size = groups[:7]
                        else:
                            continue
                        
                        # 统计IP出现次数
                        self.ip_counter[ip] += 1
                        
                        # 统计404错误
                        if status == '404':
                            self.error_404_counter[ip] += 1
                        
                        # 检查是否为Swagger请求
                        if self.is_swagger_request(path):
                            self.swagger_counter[ip] += 1
                        
                        # 检查是否为jpg或png请求
                        if path.lower().endswith('.jpg') or path.lower().endswith('.png'):
                            self.image_counter[ip] += 1
                            
                except Exception as e:
                    print(f"解析行时出错: {line}\n错误: {e}")
    
    def is_swagger_request(self, path):
        """判断是否为Swagger相关请求"""
        # 获取所有Swagger模式
        swagger_paths = self.swagger_patterns.get("swagger_paths", [])
        swagger_keywords = self.swagger_patterns.get("swagger_keywords", [])
        swagger_file_extensions = self.swagger_patterns.get("swagger_file_extensions", [])
        swagger_parameters = self.swagger_patterns.get("swagger_parameters", [])
        
        # 精确路径匹配
        if path in swagger_paths:
            return True
        
        # 关键词匹配
        for keyword in swagger_keywords:
            if keyword.lower() in path.lower():
                return True
        
        # 文件扩展名匹配
        for ext in swagger_file_extensions:
            if path.lower().endswith(ext):
                # 检查是否包含swagger关键词，以减少误报
                for keyword in swagger_keywords:
                    if keyword.lower() in path.lower():
                        return True
        
        # 参数匹配
        for param in swagger_parameters:
            if param in path:
                return True
        
        # 通配符模式匹配
        wildcard_patterns = [
            "*/swagger*",
            "*/api-docs*",
            "*/openapi*",
            "*/swagger*/ui*",
            "*/v*/api-docs*"
        ]
        
        for pattern in wildcard_patterns:
            if fnmatch.fnmatch(path.lower(), pattern):
                return True
        
        return False
    
    def analyze(self):
        """分析日志并输出统计结果"""
        self.parse_log_file()
        
        # 准备输出内容
        output = []
        output.append(f"\n{'='*50}")
        output.append(f"日志文件: {self.log_file}")
        output.append(f"{'='*50}\n")
        
        # 统计总数
        total_ips = len(self.ip_counter)
        total_requests = sum(self.ip_counter.values())
        total_404_errors = sum(self.error_404_counter.values())
        total_swagger_requests = sum(self.swagger_counter.values())
        total_image_requests = sum(self.image_counter.values())
        
        output.append(f"总统计信息:")
        output.append(f"  - 不同IP数量: {total_ips}")
        output.append(f"  - 总请求数: {total_requests}")
        output.append(f"  - 404错误总数: {total_404_errors}")
        output.append(f"  - Swagger请求总数: {total_swagger_requests}")
        output.append(f"  - 图片(jpg/png)请求总数: {total_image_requests}\n")
        
        # 输出IP详细统计
        output.append(f"IP详细统计:")
        output.append(f"{'IP地址':<20} {'总请求数':<10} {'404错误数':<10} {'Swagger请求数':<15} {'图片请求数':<10}")
        output.append(f"{'-'*65}")
        
        # 按总请求数排序
        for ip, count in sorted(self.ip_counter.items(), key=lambda x: x[1], reverse=True):
            error_404_count = self.error_404_counter.get(ip, 0)
            swagger_count = self.swagger_counter.get(ip, 0)
            image_count = self.image_counter.get(ip, 0)
            
            output.append(f"{ip:<20} {count:<10} {error_404_count:<10} {swagger_count:<15} {image_count:<10}")
        
        # 将结果输出到文件或控制台
        result = '\n'.join(output)
        
        if self.output_path:
            try:
                with open(self.output_path, 'w', encoding='utf-8') as f:
                    f.write(result)
                print(f"分析结果已保存到: {self.output_path}")
            except Exception as e:
                print(f"保存结果到文件时出错: {e}")
                print(result)  # 如果保存失败，仍然输出到控制台
        else:
            # 输出到控制台
            print(result)

def main():
    parser = argparse.ArgumentParser(description='日志分析工具 - 统计IP、404错误、Swagger请求和图片请求')
    parser.add_argument('-f', '--file', required=True, help='要分析的日志文件路径')
    parser.add_argument('-s', '--swagger', help='Swagger模式文件路径', default='swagger_patterns.json')
    parser.add_argument('-o', '--output', help='分析结果输出文件路径')
    parser.add_argument('-p', '--pattern', choices=['s', 'n', 'a'], 
                       default='s', help='日志格式类型: s=standard, n=nginx, a=apache (默认: s)')
    
    args = parser.parse_args()
    
    print(f"使用日志格式: {args.pattern}")
    analyzer = LogAnalyzer(args.file, args.swagger, args.output, args.pattern)
    analyzer.analyze()

if __name__ == "__main__":
    main()