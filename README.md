<img width="704" height="591" alt="{883CFE5D-E011-4C8D-A97D-4589EE7E0A06}" src="https://github.com/user-attachments/assets/7872c945-12d3-45d0-9057-69839a5fe85e" />用来处理访问日志
现可以处理日志正则匹配如下：
's': r'^(\S+) - - \[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "(.*)" "(.*)" "(.*)"',
'n': r'^(\S+) - - \[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "\s*(.*)\s*" "(.*)"$',
'a': r'^(\S+) - - \[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d+) (\d+)'
支持以下应用的访问日志：
- Apache HTTP Server (s格式、a格式)
- Nginx (n格式)
- IIS (如果配置为类似格式)
- Tomcat (访问日志)
- Jetty (访问日志)

使用方法：
脚本一：
用来给出日志的简略报告，会根据预设置的匹配方法，初步找到可以的访问IP和明显的漏洞利用：
执行命令 python 流量日志分析工具.py -f <文件位置> -o <存放目录位置>
结果为一个.html的网页格式，注意：若日志中有XSS攻击请求，网页可能会出现弹窗

脚本二：
用根据IP或状态码或URL等来筛选日志：
具体参数如下：
'-f', '--file', required=True, help='要分析的日志文件路径'
'-i', '--ip', metavar='OUTPUT_FILE', help='按IP过滤并输出到指定文件'
'-u', '--url', metavar='OUTPUT_FILE', help='按URL路径过滤并输出到指定文件'
'-q', '--method', metavar='OUTPUT_FILE', help='按请求方法过滤并输出到指定文件'
'-c', '--status', metavar='OUTPUT_FILE', help='按状态码过滤并输出到指定文件'
'-e', '--exclude', action='store_true', help='启用筛选模式（排除匹配项），默认为过滤模式（选取匹配项）'
'-p', '--pattern', choices=['s', 'n', 'a'], default='s', help='日志格式类型: s=standard, n=nginx, a=apache (默认: s)'

注意：每次只筛选一条规则：
命令： python 流量日志分析工具2.py -f <文件位置> <参数(如-i)> : "<参数值>:<结果文件位置>"

