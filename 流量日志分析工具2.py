import re
import argparse
import os
import datetime

# 日志解析正则表达式列表
LOG_PATTERNS = {
    's': r'^(\S+) - - \[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "(.*)" "(.*)" "(.*)"',
    'n': r'^(\S+) - - \[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "\s*(.*)\s*" "(.*)"$',
    'a': r'^(\S+) - - \[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d+) (\d+)'
}

def parse_log_file(file_path, pattern_type='s'):
    """解析日志文件"""
    log_pattern = LOG_PATTERNS.get(pattern_type, LOG_PATTERNS['s'])
    parsed_logs = []
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            try:
                match = re.match(log_pattern, line.strip())
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
                    try:
                        dt = datetime.datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z")
                        dt_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                    except:
                        dt_str = timestamp
                    
                    parsed_logs.append({
                        'ip': ip,
                        'timestamp': dt_str,
                        'method': method,
                        'path': path,
                        'protocol': protocol,
                        'status': status,
                        'size': size,
                        'referer': referer.strip() if referer else "",
                        'user_agent': user_agent if user_agent else "",
                        'extra': extra if extra else "",
                        'original_line': line.strip()
                    })
            except Exception as e:
                print(f"解析行时出错: {line}\n错误: {e}")
    return parsed_logs

def filter_by_ip(logs, ip, output_file, exclude=False):
    """按IP过滤或筛选日志"""
    if exclude:
        filtered_logs = [log for log in logs if ip not in log['ip']]
        action = "筛选（排除）"
    else:
        filtered_logs = [log for log in logs if ip in log['ip']]
        action = "过滤（选取）"
    
    # 确保输出目录存在
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # 写入过滤后的日志
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"# 按IP '{ip}' {action}的日志记录 - 共 {len(filtered_logs)} 条记录\n\n")
        for log in filtered_logs:
            f.write(f"{log['original_line']}\n")
    
    print(f"成功{action} {len(filtered_logs)} 条IP '{ip}' 的日志记录，已保存到 {output_file}")

def filter_by_path(logs, path, output_file, exclude=False):
    """按URL路径过滤或筛选日志"""
    if exclude:
        filtered_logs = [log for log in logs if path not in log['path']]
        action = "筛选（排除）"
    else:
        filtered_logs = [log for log in logs if path in log['path']]
        action = "过滤（选取）"
    
    # 确保输出目录存在
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # 写入过滤后的日志
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"# 按URL路径 '{path}' {action}的日志记录 - 共 {len(filtered_logs)} 条记录\n\n")
        for log in filtered_logs:
            f.write(f"{log['original_line']}\n")
    
    print(f"成功{action} {len(filtered_logs)} 条URL路径 '{path}' 的日志记录，已保存到 {output_file}")

def filter_by_method(logs, method, output_file, exclude=False):
    """按请求方法过滤或筛选日志"""
    if exclude:
        filtered_logs = [log for log in logs if method.upper() != log['method'].upper()]
        action = "筛选（排除）"
    else:
        filtered_logs = [log for log in logs if method.upper() == log['method'].upper()]
        action = "过滤（选取）"
    
    # 确保输出目录存在
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # 写入过滤后的日志
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"# 按请求方法 '{method}' {action}的日志记录 - 共 {len(filtered_logs)} 条记录\n\n")
        for log in filtered_logs:
            f.write(f"{log['original_line']}\n")
    
    print(f"成功{action} {len(filtered_logs)} 条请求方法 '{method}' 的日志记录，已保存到 {output_file}")

def filter_by_status(logs, status, output_file, exclude=False):
    """按状态码过滤或筛选日志"""
    if exclude:
        filtered_logs = [log for log in logs if status != log['status']]
        action = "筛选（排除）"
    else:
        filtered_logs = [log for log in logs if status == log['status']]
        action = "过滤（选取）"
    
    # 确保输出目录存在
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # 写入过滤后的日志
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"# 按状态码 '{status}' {action}的日志记录 - 共 {len(filtered_logs)} 条记录\n\n")
        for log in filtered_logs:
            f.write(f"{log['original_line']}\n")
    
    print(f"成功{action} {len(filtered_logs)} 条状态码 '{status}' 的日志记录，已保存到 {output_file}")

def main():
    parser = argparse.ArgumentParser(description='日志分析工具 - 按IP、URL路径、请求方法或状态码过滤/筛选日志')
    parser.add_argument('-f', '--file', required=True, help='要分析的日志文件路径')
    parser.add_argument('-i', '--ip', metavar='OUTPUT_FILE', help='按IP过滤并输出到指定文件')
    parser.add_argument('-u', '--url', metavar='OUTPUT_FILE', help='按URL路径过滤并输出到指定文件')
    parser.add_argument('-q', '--method', metavar='OUTPUT_FILE', help='按请求方法过滤并输出到指定文件')
    parser.add_argument('-c', '--status', metavar='OUTPUT_FILE', help='按状态码过滤并输出到指定文件')
    parser.add_argument('-e', '--exclude', action='store_true', help='启用筛选模式（排除匹配项），默认为过滤模式（选取匹配项）')
    parser.add_argument('-p', '--pattern', choices=['s', 'n', 'a'], 
                       default='s', help='日志格式类型: s=standard, n=nginx, a=apache (默认: s)')
    
    args = parser.parse_args()
    
    # 检查是否提供了至少一个过滤选项
    if not (args.ip or args.url or args.method or args.status):
        parser.error("请至少指定一个过滤选项: -i (IP), -u (URL路径), -q (请求方法) 或 -c (状态码)")
    
    # 检查是否提供了多个过滤选项
    filter_count = sum(1 for x in [args.ip, args.url, args.method, args.status] if x)
    if filter_count > 1:
        parser.error("请只指定一个过滤选项: -i (IP), -u (URL路径), -q (请求方法) 或 -c (状态码)")
    
    # 解析日志文件
    print(f"正在解析日志文件: {args.file}")
    print(f"使用日志格式: {args.pattern}")
    logs = parse_log_file(args.file, args.pattern)
    print(f"成功解析 {len(logs)} 条日志记录")
    
    # 根据选项进行过滤或筛选
    if args.ip:
        filter_by_ip(logs, args.ip.split(':')[0], args.ip.split(':', 1)[1] if ':' in args.ip else args.ip, args.exclude)
    elif args.url:
        filter_by_path(logs, args.url.split(':')[0], args.url.split(':', 1)[1] if ':' in args.url else args.url, args.exclude)
    elif args.method:
        filter_by_method(logs, args.method.split(':')[0], args.method.split(':', 1)[1] if ':' in args.method else args.method, args.exclude)
    elif args.status:
        filter_by_status(logs, args.status.split(':')[0], args.status.split(':', 1)[1] if ':' in args.status else args.status, args.exclude)

if __name__ == "__main__":
    main()