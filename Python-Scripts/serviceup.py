#!/usr/bin/env python3

#Made By 1one0zero

#This script is a cross-platform system integrity monitoring tool that tracks changes to specified files and directories on Linux and Windows systems. Its key features include:

    #OS Detection: Automatically identifies the operating system and uses appropriate methods for monitoring.
    #Linux Monitoring:
        #Uses the pyinotify library to detect events such as file modifications, creations, deletions, and attribute changes.
        #Supports monitoring both individual files and directories (recursively).
    #Windows Monitoring:
        #Uses pywin32 to track changes in directories, including file creation, deletion, modification, renaming, and attribute changes.
        #Limited to directory monitoring (not individual files).
    #Customizable Monitoring List:
        #Predefined sensitive files and directories (e.g., /etc/passwd, /etc/ssh/sshd_config).
        #Alerts users with details about the type of change, the affected file/directory, and its path.

#This tool is ideal for system administrators or security professionals who need to detect unauthorized changes to critical system files or configurations in real-time.
#Usage of this script has no responsibiity on its creator, use at your own risk.

import os
import time
import platform
import subprocess
import re

def get_os():
    """
    Detect the operating system.
    Returns:
        str: 'Windows' or 'Linux'
    """
    return platform.system()

def get_all_services_windows():
    """
    Get a dictionary of all Windows services and their statuses.
    Returns:
        dict: {service_name: status}
    """
    cmd = 'sc query state= all'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
    output = result.stdout
    services = {}
    service_name = ''
    for line in output.splitlines():
        line = line.strip()
        if line.startswith('SERVICE_NAME:'):
            service_name = line.split(':',1)[1].strip()
        elif line.startswith('STATE'):
            # STATE              : 4  RUNNING
            parts = line.split(':',1)[1].strip().split()
            if len(parts) >= 2:
                state_code = parts[0]
                state_text = parts[1]
                services[service_name] = state_text
    return services

def start_service_windows(service_name):
    """
    Start a Windows service.
    Args:
        service_name (str): Name of the service.
    Returns:
        bool: True if started successfully, False otherwise.
    """
    cmd = f'sc start "{service_name}"'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
    return result.returncode == 0

def get_all_services_linux():
    """
    Get a dictionary of all Linux services and their statuses.
    Returns:
        dict: {service_name: status}
    """
    cmd = 'systemctl list-units --type=service --all --no-pager --no-legend'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
    output = result.stdout.strip()
    services = {}
    for line in output.split('\n'):
        if line.strip():
            # Each line contains: UNIT LOAD ACTIVE SUB DESCRIPTION
            parts = line.split()
            if len(parts) >= 4:
                service_name = parts[0]
                load = parts[1]
                active = parts[2]
                services[service_name] = active
    return services

def start_service_linux(service_name):
    """
    Start a Linux service.
    Args:
        service_name (str): Name of the service.
    Returns:
        bool: True if started successfully, False otherwise.
    """
    cmd = f'sudo systemctl start {service_name}'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
    return result.returncode == 0

def get_service_terminator(service_name, os_type):
    """
    Attempt to find out who stopped the service.
    Args:
        service_name (str): Name of the service.
        os_type (str): Operating system type.
    Returns:
        str: Username of the person who terminated the service, or 'Unknown User'.
    """
    if os_type == 'Linux':
        cmd = f'journalctl _SYSTEMD_UNIT={service_name} -n 50'
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
        output = result.stdout
        matches = re.findall(r'Stopped\s+.*\s+by\s+user\s+(\w+)', output)
        if matches:
            return matches[-1]
    # For Windows or if no match found
    return "Unknown User"

def monitor_services():
    """
    Monitor all services and prompt the user if any service stops.
    """
    os_type = get_os()
    if os_type == 'Windows':
        get_all_services = get_all_services_windows
        start_service = start_service_windows
    elif os_type == 'Linux':
        get_all_services = get_all_services_linux
        start_service = start_service_linux
    else:
        print("Unsupported OS")
        return

    # Get initial list of services and their statuses
    services_status = get_all_services()
    previous_status = services_status.copy()

    print(f"Monitoring all services ({len(services_status)} services detected)...\n")

    try:
        while True:
            services_status = get_all_services()
            # Clear the console
            os.system('cls' if os.name == 'nt' else 'clear')
            # Print out the status of all services
            print(f"{'Service Name':<50} {'Status':<10}")
            print('-'*60)
            for service, status in sorted(services_status.items()):
                print(f"{service:<50} {status:<10}")
            # Compare current statuses with previous statuses
            for service, status in services_status.items():
                prev_status = previous_status.get(service, None)
                if prev_status != status:
                    if status.lower() in ["stopped", "inactive", "failed", "stop_pending", "paused"]:
                        # Service has stopped
                        terminator = get_service_terminator(service, os_type)
                        print(f"\nService '{service}' has been terminated by {terminator}.")
                        response = input(f"Do you want to restart '{service}'? (yes/no): ").strip().lower()
                        if response == 'yes':
                            success = start_service(service)
                            if success:
                                print(f"Service '{service}' has been started.")
                                previous_status[service] = status
                            else:
                                print(f"Failed to start service '{service}'.")
                        else:
                            print(f"Service '{service}' will remain stopped.")
                            previous_status[service] = status
                    else:
                        print(f"\nService '{service}' status changed from '{prev_status}' to '{status}'.")
                        previous_status[service] = status
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")

if __name__ == "__main__":
    monitor_services()
