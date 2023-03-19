"""PCAP Getter Utility.

Example Command line runner

python3 nelly/get_pcap.py --device 172.200.100.13 --interface GigabitEthernet1 --username admin --duration 10
"""
import argparse
import re
import sys
import time
from datetime import datetime
from getpass import getpass, getuser
from typing import List, Union

import netmiko
import textfsm
from loguru import logger
from netmiko import ConnectHandler, file_transfer


def parse_arguments() -> argparse.Namespace:
    """
    Parse command line arguments.
    Returns:
        Namespace: Parsed command line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Capture packets on a Cisco IOS XE device using Netmiko."
    )

    parser.add_argument(
        "--device",
        required=True,
        help="IP address or hostname of the Cisco IOS XE device",
    )
    parser.add_argument(
        "--username",
        default=getuser(),
        help="Username for authentication (default: current user)",
    )
    parser.add_argument(
        "--interface",
        required=True,
        help="Interface to monitor, e.g. GigabitEthernet0/0",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=30,
        help="Duration to run the packet capture (in seconds)",
    )
    current_timestamp = datetime.now().strftime("%Y%m%d")
    default_session_name = f"pcap_{current_timestamp}"
    logger.info(f"Using default session name {default_session_name}")
    parser.add_argument(
        "--monitor-session-name",
        default=default_session_name,
        help="Monitor session name for the packet capture (default: pcap_<timestamp>)",
    )
    args = parser.parse_args()

    # Validate that the provided monitor session name contains only alphanumeric characters and underscores
    if not re.match("^[a-zA-Z0-9_]*$", args.monitor_session_name):
        parser.error(
            "The monitor session name can only contain alphanumeric characters and underscores (_)."
        )

    return args


def is_scp_enabled(connection) -> None:
    output = connection.send_command(
        "show running-config | include ip scp server enable"
    )
    if "ip scp server enable" in output:
        logger.info("SCP is enabled on the device")
    else:
        sys.exit("SCP is not enabled on the device. Exiting.")


def validate_interface(connection: ConnectHandler, interface: str) -> Union[bool, None]:
    """
    Validate if the provided interface is present in the output of 'show ip int brief' command.
    Args:
        connection (ConnectHandler): Connection to the device.
        interface (str): Interface to validate.
    Returns:
        bool: True if the interface is present, None if the script exits due to an error.
    """
    raw_output = connection.send_command("show ip int brief", use_textfsm=True)
    for item in raw_output:
        if item["intf"] == interface:
            return True
    logger.error(
        f"Provided interface '{interface}' not found in 'show ip int brief' output. Please provide a correct interface."
    )
    interfaces = [interface["intf"] for interface in raw_output]
    sys.exit(
        f"Invalid interface provided. It must be an exact match. Available interfaces: {interfaces}"
    )


def generate_unique_pcap_name(device_name: str) -> str:
    """
    Generate a unique pcap file name based on the device_name and current timestamp.
    Args:
        device_files (List[str]): List of existing device files.
        device_name (str): Name of the device.

    Returns:
        str: Unique pcap file name.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"{device_name}_capture_{timestamp}.pcap"

    return base_name


def is_enough_space(dir_output: str, required_space: int = 2048) -> bool:
    """
    Check if there is enough space in the device's flash directory.
    Args:
        dir_output (str): Output of 'dir flash:' command.
        required_space (int, optional): Required space in KB. Defaults to 2048.

    Returns:
        bool: True if there is enough space, False otherwise.
    """
    template_file = "cisco_ios_show_dir_flash.template"
    with open(template_file) as f:
        fsm = textfsm.TextFSM(f)
    fsm_results = fsm.ParseText(dir_output)
    for row in fsm_results:
        available_space = int(row[1])
        if available_space > required_space:
            return True
    return False


def start_capture(connection, interface: str, monitor_session_name: str) -> None:
    """
    Start packet capture on the specified interface.
    Args:
        connection: Connection to the device.
        interface (str): Interface to monitor.
        monitor_session_name (str): Monitor session name for the packet capture.
    """
    capture_config = [
        f"monitor capture {monitor_session_name} interface {interface} both",
        f"monitor capture {monitor_session_name} match ipv4 any any",
        f"monitor capture {monitor_session_name} start",
    ]
    logger.debug(f"Capture config: {capture_config}")
    for command in capture_config:
        logger.debug(f"COMMAND DISPATCH: {command}")
        try:
            cap_cmd = connection.send_command(command, delay_factor=2, read_timeout=5)
        except netmiko.exceptions.ReadTimeout:
            connection.find_prompt()
            cap_cmd = connection.send_command_expect(
                command, delay_factor=2, expect_string="confirm", read_timeout=5
            )
            cap_cmd = connection.send_command("yes")
        logger.info(f"Configured packet capture \n {cap_cmd}")
        if "Invalid input detected" in cap_cmd:
            logger.error("Invalid input detected. Aborting.")
            sys.exit("Invalid input detected. Aborting.")


def stop_capture(connection, monitor_session_name: str) -> None:
    """
    Stop the packet capture.
    Args:
        connection: Connection to the device.
        monitor_session_name (str): Monitor session name for the packet capture.
    """
    command = f"monitor capture {monitor_session_name} stop"
    logger.debug(f"COMMAND DISPATCH: {command}")
    cap_cmd = connection.send_command(command)
    logger.info(f"Stopped packet capture \n {cap_cmd}")


def export_capture(
    connection: ConnectHandler, pcap_file: str, monitor_session_name: str
) -> None:
    """
    Export the packet capture to the device's flash storage.
    Args:
        connection (ConnectHandler): Connection to the device.
        pcap_file (str): Name of the pcap file.
        monitor_session_name (str): Monitor session name for the packet capture.
    """
    export_cmd = f"monitor capture {monitor_session_name} export flash:{pcap_file}"
    logger.debug(f"COMMAND DISPATCH: {export_cmd}")
    cmd = connection.send_command(export_cmd)
    if not "Successfully" in cmd:
        sys.exit(f"Failed to export packet capture \n {cmd}")
    logger.info(f"Exported packet capture \n {cmd}")


def retrieve_capture(connection: ConnectHandler, pcap_file: str) -> None:
    """
    Retrieve the packet capture file using SCP.
    Args:
        connection (ConnectHandler): Connection to the device.
        pcap_file (str): Name of the pcap file.
    """
    logger.info(f"Attemping to pull PCAP {pcap_file} from device")
    transfer_dict = file_transfer(
        connection,
        source_file=pcap_file,
        dest_file=pcap_file,
        file_system="flash:",
        direction="get",
        overwrite_file=True,
    )
    logger.debug(f"File transfer dict result: {transfer_dict}")
    logger.info(f"Retrieved packet capture using SCP: {pcap_file}")


def delete_capture(connection: ConnectHandler, pcap_file: str) -> None:
    """
    Delete the packet capture file from the device's flash storage.
    Args:
        connection (ConnectHandler): Connection to the device.
        pcap_file (str): Name of the pcap file.
    """
    command = f"delete flash:{pcap_file}"
    output = connection.send_command_expect(
        command, delay_factor=2, expect_string="pcap", read_timeout=10, max_loops=1000
    )
    connection.find_prompt()
    logger.debug(f"Delete command output: {output}")
    connection.send_command("\n")
    output = connection.send_command_expect(
        command, delay_factor=2, expect_string="pcap", read_timeout=10, max_loops=1000
    )
    connection.find_prompt()
    logger.debug(f"Delete confirm output: {output}")
    connection.send_command("\n")
    logger.info("Removed packet capture file from the device")


def cleanup_capture(connection: ConnectHandler, monitor_session_name: str) -> None:
    """
    Clean up the capture configuration on the device.
    Args:
        connection (ConnectHandler): Connection to the device.
        monitor_session_name (str): Monitor session name for the packet capture.
    """
    cmd = f"no monitor capture {monitor_session_name}"
    logger.debug(f"COMMAND DISPATCH: {cmd}")
    cmd = connection.send_command(cmd)
    logger.info(f"Cleaned up capture configuration.")


def contains_pcap_files(output: str) -> bool:
    pattern = r"\S+\.pcap"
    pcap_files = re.findall(pattern, output)
    return bool(pcap_files)


def validate(connection: ConnectHandler, interface: str) -> str:
    # Get device name
    device_name = connection.send_command(
        "show running-config | include hostname"
    ).split()[1]
    logger.info(f"Connected to {device_name}")
    # Validate the provided interface
    validate_interface(connection, interface)
    is_scp_enabled(connection)
    dir_output = connection.send_command("dir flash:")
    logger.info("Checking Flash..")
    logger.info(dir_output)
    device_files = connection.send_command("dir flash: | include pcap")
    if contains_pcap_files(device_files):
        logger.warning(
            f"Found existing pcap files. Consider cleaning up Flash. \n{device_files}"
        )
    return device_name


def packet_capture(
    device: str,
    username: str,
    password: str,
    interface: str,
    duration: int,
    monitor_session_name: str,
) -> None:
    """
    Perform packet capture on a Cisco IOS XE device using Netmiko.
    Args:
        device (str): IP address or hostname of the device.
        username (str): Username for authentication.
        password (str): Password for authentication.
        interface (str): Interface to monitor.
        duration (int): Duration to run the packet capture (in seconds).
        monitor_session_set (str): Monitor session name for the packet capture.
    """
    connection = ConnectHandler(
        device_type="cisco_ios",
        ip=device,
        username=username,
        password=password,
        fast_cli=False,
        session_log="session.log",
    )
    device_name = validate(connection, interface)
    logger.info(f"Validated {device_name} and procceeding with packet capture")
    pcap_file = generate_unique_pcap_name(device_name)
    logger.info(f"Generated unique pcap file name: {pcap_file}")
    start_capture(connection, interface, monitor_session_name)
    logger.info("Started packet capture")
    time.sleep(duration)
    connection.find_prompt()
    stop_capture(connection, monitor_session_name)
    logger.info("Stopped packet capture")
    export_capture(connection, pcap_file, monitor_session_name)
    cleanup_capture(connection, monitor_session_name)
    retrieve_capture(connection, pcap_file)
    delete_capture(connection, pcap_file)
    connection.disconnect()
    logger.info("Disconnected from the device")


if __name__ == "__main__":
    args = parse_arguments()
    # device_password = getpass("Password: ")
    device_password = "admin"
    packet_capture(
        device=args.device,
        username=args.username,
        password=device_password,
        interface=args.interface,
        duration=args.duration,
        monitor_session_name=args.monitor_session_name,
    )
