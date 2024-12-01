import platform
import socket
import subprocess
import os
import re
from datetime import datetime, timedelta

def get_ip():
    # Get the first non-loopback IP address
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def save_to_file(filename, content):
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(content)

def get_system_info():
    os_type = platform.system()
    if os_type == 'Windows':
        info = get_windows_info()
    elif os_type == 'Linux':
        info = get_linux_info()
    elif os_type == 'FreeBSD':
        info = get_freebsd_info()
    else:
        info = "Unsupported OS\n"
    return info

def get_windows_info():
    info = ''
    info += '========== System Information ==========\n'
    info += 'Operating System: ' + platform.platform() + '\n'
    info += 'Hostname: ' + platform.node() + '\n'
    info += '\n========== Installed Software ==========\n'
    info += get_installed_software_windows()
    info += '\n========== Running Services ==========\n'
    info += get_running_services_windows()
    info += '\n========== Open Ports ==========\n'
    info += get_open_ports_windows()
    info += '\n========== Network Configuration ==========\n'
    info += get_network_config_windows()
    info += '\n========== Users and Groups ==========\n'
    info += get_users_groups_windows()
    info += '\n========== Active Connections ==========\n'
    info += get_active_connections_windows()
    info += '\n========== Security Policies ==========\n'
    info += get_security_policies_windows()
    info += '\n========== Firewall Rules ==========\n'
    info += get_firewall_rules_windows()
    # Additional sections for APT501 detection
    info += '\n========== Recent PowerShell and CMD Usage ==========\n'
    info += get_recent_shell_usage_windows()
    info += '\n========== Suspicious Recent Files ==========\n'
    info += get_suspicious_recent_files_windows()
    info += '\n========== Recent Account Changes ==========\n'
    info += get_recent_account_changes_windows()
    info += '\n========== Potential Web Shells ==========\n'
    info += get_potential_webshells_windows()
    info += '\n========== Active SMB Sessions ==========\n'
    info += get_active_smb_sessions_windows()
    info += '\n========== Proxy Settings ==========\n'
    info += get_proxy_settings_windows()
    return info

def get_linux_info():
    info = ''
    info += '========== System Information ==========\n'
    info += 'Operating System: ' + platform.platform() + '\n'
    info += 'Hostname: ' + platform.node() + '\n'
    info += '\n========== Installed Software ==========\n'
    info += get_installed_software_linux()
    info += '\n========== Running Services ==========\n'
    info += get_running_services_linux()
    info += '\n========== Open Ports ==========\n'
    info += get_open_ports_linux()
    info += '\n========== Network Configuration ==========\n'
    info += get_network_config_linux()
    info += '\n========== Users and Groups ==========\n'
    info += get_users_groups_linux()
    info += '\n========== Active Connections ==========\n'
    info += get_active_connections_linux()
    info += '\n========== Security Policies ==========\n'
    info += get_security_policies_linux()
    info += '\n========== Firewall Rules ==========\n'
    info += get_firewall_rules_linux()
    # Additional sections for APT501 detection
    info += '\n========== Recent Shell History ==========\n'
    info += get_recent_shell_history_linux()
    info += '\n========== Suspicious Recent Files ==========\n'
    info += get_suspicious_recent_files_linux()
    info += '\n========== Recent Account Changes ==========\n'
    info += get_recent_account_changes_linux()
    info += '\n========== Potential Web Shells ==========\n'
    info += get_potential_webshells_linux()
    info += '\n========== Active SMB Sessions ==========\n'
    info += get_active_smb_sessions_linux()
    info += '\n========== Proxy Settings ==========\n'
    info += get_proxy_settings_linux()
    return info

def get_freebsd_info():
    info = ''
    info += '========== System Information ==========\n'
    info += 'Operating System: ' + platform.platform() + '\n'
    info += 'Hostname: ' + platform.node() + '\n'
    info += '\n========== Installed Software ==========\n'
    info += get_installed_software_freebsd()
    info += '\n========== Running Services ==========\n'
    info += get_running_services_freebsd()
    info += '\n========== Open Ports ==========\n'
    info += get_open_ports_freebsd()
    info += '\n========== Network Configuration ==========\n'
    info += get_network_config_freebsd()
    info += '\n========== Users and Groups ==========\n'
    info += get_users_groups_freebsd()
    info += '\n========== Active Connections ==========\n'
    info += get_active_connections_freebsd()
    info += '\n========== Security Policies ==========\n'
    info += get_security_policies_freebsd()
    info += '\n========== Firewall Rules ==========\n'
    info += get_firewall_rules_freebsd()
    # Additional sections for APT501 detection
    info += '\n========== Recent Shell History ==========\n'
    info += get_recent_shell_history_freebsd()
    info += '\n========== Suspicious Recent Files ==========\n'
    info += get_suspicious_recent_files_freebsd()
    info += '\n========== Recent Account Changes ==========\n'
    info += get_recent_account_changes_freebsd()
    info += '\n========== Potential Web Shells ==========\n'
    info += get_potential_webshells_freebsd()
    info += '\n========== Active SMB Sessions ==========\n'
    info += get_active_smb_sessions_freebsd()
    info += '\n========== Proxy Settings ==========\n'
    info += get_proxy_settings_freebsd()
    return info

# Windows Functions

def get_installed_software_windows():
    cmd = 'wmic product get Name, Version'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    return result.stdout or result.stderr

def get_running_services_windows():
    cmd = 'tasklist /svc'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    return result.stdout or result.stderr

def get_open_ports_windows():
    cmd = 'netstat -ano'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    return result.stdout or result.stderr

def get_network_config_windows():
    cmd = 'ipconfig /all'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    return result.stdout or result.stderr

def get_users_groups_windows():
    cmd_users = 'net user'
    result_users = subprocess.run(cmd_users, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    cmd_groups = 'net localgroup'
    result_groups = subprocess.run(cmd_groups, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    return 'Users:\n' + (result_users.stdout or result_users.stderr) + '\nGroups:\n' + (result_groups.stdout or result_groups.stderr)

def get_active_connections_windows():
    cmd = 'netstat -an'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    return result.stdout or result.stderr

def get_security_policies_windows():
    # Export security policies to a temporary file
    cmd = 'secedit /export /cfg secedit_tmp.inf'
    subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    try:
        with open('secedit_tmp.inf', 'r', encoding='utf-16') as f:
            data = f.read()
    except Exception as e:
        data = f"Could not read security policies: {e}\n"
    finally:
        if os.path.exists('secedit_tmp.inf'):
            os.remove('secedit_tmp.inf')
    return data

def get_firewall_rules_windows():
    cmd = 'netsh advfirewall firewall show rule name=all'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    return result.stdout or result.stderr

def get_recent_shell_usage_windows():
    info = ''
    # Get the last 7 days of PowerShell and CMD logs
    cmd = 'wevtutil qe "Windows PowerShell" /q:"*[System[(TimeCreated[timediff(@SystemTime) <= 604800000])]]" /f:text'
    result_ps = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    info += 'PowerShell Logs:\n' + (result_ps.stdout or result_ps.stderr) + '\n'
    cmd = 'wevtutil qe "Microsoft-Windows-Cmd/Operational" /q:"*[System[(TimeCreated[timediff(@SystemTime) <= 604800000])]]" /f:text'
    result_cmd = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    info += 'CMD Logs:\n' + (result_cmd.stdout or result_cmd.stderr)
    return info

def get_suspicious_recent_files_windows():
    # Look for recent files in Downloads and Temp directories
    paths = [os.environ.get('USERPROFILE') + '\\Downloads', os.environ.get('TEMP')]
    info = ''
    now = datetime.now()
    for path in paths:
        if os.path.exists(path):
            info += f'Files in {path} modified in the last 7 days:\n'
            for root, dirs, files in os.walk(path):
                for file in files:
                    filepath = os.path.join(root, file)
                    try:
                        mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                        if (now - mtime) < timedelta(days=7):
                            info += f'{filepath} - Last Modified: {mtime}\n'
                    except Exception as e:
                        info += f'Error accessing {filepath}: {e}\n'
    return info

def get_recent_account_changes_windows():
    cmd = 'net user'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    users = re.findall(r'\b\w+\b', result.stdout)
    info = ''
    for user in users:
        cmd = f'net user {user}'
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
        match = re.search(r'Account active\s+(\w+)', result.stdout)
        if match:
            info += f'User: {user}, Account Active: {match.group(1)}\n'
    return info

def get_potential_webshells_windows():
    # Check common web directories for files modified in the last 7 days
    paths = ['C:\\inetpub\\wwwroot', 'C:\\xampp\\htdocs']
    info = ''
    now = datetime.now()
    for path in paths:
        if os.path.exists(path):
            info += f'Files in {path} modified in the last 7 days:\n'
            for root, dirs, files in os.walk(path):
                for file in files:
                    if file.endswith(('.asp', '.aspx', '.php', '.jsp')):
                        filepath = os.path.join(root, file)
                        try:
                            mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                            if (now - mtime) < timedelta(days=7):
                                info += f'{filepath} - Last Modified: {mtime}\n'
                        except Exception as e:
                            info += f'Error accessing {filepath}: {e}\n'
    return info

def get_active_smb_sessions_windows():
    cmd = 'net session'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    return result.stdout or result.stderr

def get_proxy_settings_windows():
    cmd = 'netsh winhttp show proxy'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    return result.stdout or result.stderr

# Linux Functions

def get_installed_software_linux():
    if os.path.exists('/usr/bin/dpkg'):
        cmd = 'dpkg -l'
    elif os.path.exists('/usr/bin/rpm'):
        cmd = 'rpm -qa'
    else:
        return 'Package manager not detected.\n'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    return result.stdout or result.stderr

def get_running_services_linux():
    cmd = 'systemctl list-units --type=service --state=running'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    return result.stdout or result.stderr

def get_open_ports_linux():
    cmd = 'netstat -tuln'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    if 'command not found' in result.stderr:
        cmd = 'ss -tuln'
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    return result.stdout or result.stderr

def get_network_config_linux():
    cmd = 'ifconfig -a'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    if 'command not found' in result.stderr:
        cmd = 'ip addr show'
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    return result.stdout or result.stderr

def get_users_groups_linux():
    try:
        with open('/etc/passwd', 'r') as f:
            passwd = f.read()
        with open('/etc/group', 'r') as f:
            group = f.read()
        return 'Users (/etc/passwd):\n' + passwd + '\nGroups (/etc/group):\n' + group
    except Exception as e:
        return f"Could not read users/groups: {e}\n"

def get_active_connections_linux():
    cmd = 'netstat -an'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    if 'command not found' in result.stderr:
        cmd = 'ss -an'
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    return result.stdout or result.stderr

def get_security_policies_linux():
    if os.path.exists('/usr/sbin/sestatus'):
        cmd = 'sestatus'
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
        return result.stdout or result.stderr
    else:
        return 'SELinux not installed or not enabled.\n'

def get_firewall_rules_linux():
    cmd = 'iptables -L -n -v'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    if result.returncode != 0:
        cmd = 'firewall-cmd --list-all'
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    return result.stdout or result.stderr

def get_recent_shell_history_linux():
    info = ''
    # Read shell history
    home_dirs = [os.path.join('/home', d) for d in os.listdir('/home')]
    for home in home_dirs:
        history_file = os.path.join(home, '.bash_history')
        if os.path.exists(history_file):
            info += f'History for {home}:\n'
            try:
                with open(history_file, 'r') as f:
                    info += f.read() + '\n'
            except Exception as e:
                info += f'Error reading {history_file}: {e}\n'
    return info

def get_suspicious_recent_files_linux():
    # Look for recent files in Downloads and /tmp directories
    paths = ['/tmp', '/var/tmp']
    home_dirs = [os.path.join('/home', d, 'Downloads') for d in os.listdir('/home')]
    paths.extend(home_dirs)
    info = ''
    now = datetime.now()
    for path in paths:
        if os.path.exists(path):
            info += f'Files in {path} modified in the last 7 days:\n'
            for root, dirs, files in os.walk(path):
                for file in files:
                    filepath = os.path.join(root, file)
                    try:
                        mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                        if (now - mtime) < timedelta(days=7):
                            info += f'{filepath} - Last Modified: {mtime}\n'
                    except Exception as e:
                        info += f'Error accessing {filepath}: {e}\n'
    return info

def get_recent_account_changes_linux():
    cmd = 'lastlog -t 7'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    return result.stdout or result.stderr

def get_potential_webshells_linux():
    # Check common web directories for files modified in the last 7 days
    paths = ['/var/www/html', '/usr/share/nginx/html']
    info = ''
    now = datetime.now()
    for path in paths:
        if os.path.exists(path):
            info += f'Files in {path} modified in the last 7 days:\n'
            for root, dirs, files in os.walk(path):
                for file in files:
                    if file.endswith(('.php', '.jsp', '.asp', '.aspx')):
                        filepath = os.path.join(root, file)
                        try:
                            mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                            if (now - mtime) < timedelta(days=7):
                                info += f'{filepath} - Last Modified: {mtime}\n'
                        except Exception as e:
                            info += f'Error accessing {filepath}: {e}\n'
    return info

def get_active_smb_sessions_linux():
    cmd = 'smbstatus --shares'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    return result.stdout or result.stderr

def get_proxy_settings_linux():
    # Check environment variables for proxy settings
    proxy_vars = ['http_proxy', 'https_proxy', 'ftp_proxy', 'no_proxy']
    info = ''
    for var in proxy_vars:
        value = os.environ.get(var)
        if value:
            info += f'{var}={value}\n'
    return info

# FreeBSD Functions

def get_installed_software_freebsd():
    cmd = 'pkg info'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    if result.returncode != 0:
        return 'Could not retrieve installed packages.\n' + (result.stderr or '')
    return result.stdout

def get_running_services_freebsd():
    cmd = 'service -e'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    return result.stdout or result.stderr

def get_open_ports_freebsd():
    cmd = 'sockstat -4 -l'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    return result.stdout or result.stderr

def get_network_config_freebsd():
    cmd = 'ifconfig -a'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    return result.stdout or result.stderr

def get_users_groups_freebsd():
    try:
        with open('/etc/passwd', 'r') as f:
            passwd = f.read()
        with open('/etc/group', 'r') as f:
            group = f.read()
        return 'Users (/etc/passwd):\n' + passwd + '\nGroups (/etc/group):\n' + group
    except Exception as e:
        return f"Could not read users/groups: {e}\n"

def get_active_connections_freebsd():
    cmd = 'netstat -an'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    return result.stdout or result.stderr

def get_security_policies_freebsd():
    cmd = 'sysctl security'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    return result.stdout or result.stderr

def get_firewall_rules_freebsd():
    # Check for pf firewall rules
    cmd = 'pfctl -sr'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    if result.returncode == 0:
        return result.stdout
    else:
        # Check for ipfw firewall rules
        cmd = 'ipfw list'
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    return result.stdout or result.stderr

def get_recent_shell_history_freebsd():
    info = ''
    # Read shell history
    home_dirs = [os.path.join('/home', d) for d in os.listdir('/home') if os.path.isdir(os.path.join('/home', d))]
    for home in home_dirs:
        history_files = ['.bash_history', '.sh_history', '.cshrc', '.zsh_history']
        for hist_file in history_files:
            history_path = os.path.join(home, hist_file)
            if os.path.exists(history_path):
                info += f'History file {hist_file} for {home}:\n'
                try:
                    with open(history_path, 'r') as f:
                        info += f.read() + '\n'
                except Exception as e:
                    info += f'Error reading {history_path}: {e}\n'
    return info

def get_suspicious_recent_files_freebsd():
    # Look for recent files in /tmp and user Downloads directories
    paths = ['/tmp', '/var/tmp']
    home_dirs = [os.path.join('/home', d, 'Downloads') for d in os.listdir('/home') if os.path.isdir(os.path.join('/home', d))]
    paths.extend(home_dirs)
    info = ''
    now = datetime.now()
    for path in paths:
        if os.path.exists(path):
            info += f'Files in {path} modified in the last 7 days:\n'
            for root, dirs, files in os.walk(path):
                for file in files:
                    filepath = os.path.join(root, file)
                    try:
                        mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                        if (now - mtime) < timedelta(days=7):
                            info += f'{filepath} - Last Modified: {mtime}\n'
                    except Exception as e:
                        info += f'Error accessing {filepath}: {e}\n'
    return info

def get_recent_account_changes_freebsd():
    cmd = 'last -n 100'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    info = 'Recent logins (last 7 days):\n'
    now = datetime.now()
    for line in result.stdout.splitlines():
        match = re.match(r'^(\w+)\s', line)
        if match:
            username = match.group(1)
            # Extract date string from line
            date_str = ' '.join(line.split()[-4:])
            try:
                log_time = datetime.strptime(date_str, '%a %b %d %H:%M:%S %Y')
                if (now - log_time) < timedelta(days=7):
                    info += line + '\n'
            except Exception:
                continue
    return info

def get_potential_webshells_freebsd():
    # Check common web directories for files modified in the last 7 days
    paths = ['/usr/local/www/apache24/data', '/usr/local/www/nginx']
    info = ''
    now = datetime.now()
    for path in paths:
        if os.path.exists(path):
            info += f'Files in {path} modified in the last 7 days:\n'
            for root, dirs, files in os.walk(path):
                for file in files:
                    if file.endswith(('.php', '.jsp', '.asp', '.aspx')):
                        filepath = os.path.join(root, file)
                        try:
                            mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                            if (now - mtime) < timedelta(days=7):
                                info += f'{filepath} - Last Modified: {mtime}\n'
                        except Exception as e:
                            info += f'Error accessing {filepath}: {e}\n'
    return info

def get_active_smb_sessions_freebsd():
    cmd = 'smbstatus'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    if 'command not found' in result.stderr:
        return 'SMB not installed or smbstatus command not found.\n'
    return result.stdout or result.stderr

def get_proxy_settings_freebsd():
    # Check environment variables for proxy settings
    proxy_vars = ['http_proxy', 'https_proxy', 'ftp_proxy', 'no_proxy']
    info = ''
    for var in proxy_vars:
        value = os.environ.get(var)
        if value:
            info += f'{var}={value}\n'
    return info

def main():
    ip = get_ip()
    filename = ip.replace('.', '_') + '.txt'
    content = get_system_info()
    save_to_file(filename, content)
    print(f"System information saved to {filename}")

if __name__ == '__main__':
    main()
