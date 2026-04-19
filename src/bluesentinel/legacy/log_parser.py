import re
from datetime import datetime

LOG_PATTERN = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s(?P<host>\S+)\s(?P<process>\S+)\[(?P<pid>\d+)\]:\s(?P<message>.+)$'
)

def parse_log(file_path):
    parsed_logs = []

    with open(file_path, 'r') as file:
        for line in file:
            match = LOG_PATTERN.match(line.strip())
            if match:
                log_data = match.groupdict()
                log_data["timestamp"] = parse_timestamp(log_data)
                parsed_logs.append(log_data)

    return parsed_logs

def parse_timestamp(log):
    current_year = datetime.now().year
    log_time_str = f"{log['month']} {log['day']} {current_year} {log['time']}"
    return datetime.strptime(log_time_str, "%b %d %Y %H:%M:%S")
