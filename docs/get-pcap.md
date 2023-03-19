# Packet Capture Tool for Cisco IOS XE Devices

This Python script utilizes Netmiko to capture packets on a Cisco IOS XE device. The script requires that the device has SCP enabled for file transfer. The script performs the following steps:

1. Parse command line arguments
2. Validate the provided interface, check if SCP is enabled, and if there is enough space on the device's flash storage
3. Start the packet capture on the specified interface
4. Wait for the specified duration
5. Stop the packet capture
6. Export the packet capture to the device's flash storage
7. Retrieve the packet capture file using SCP
8. Delete the packet capture file from the device's flash storage
9. Clean up the capture configuration on the device
10. Disconnect from the device

## Functions

### `parse_arguments() -> argparse.Namespace`

This function parses the command line arguments and returns a Namespace object containing the parsed arguments.

### `is_scp_enabled(connection) -> None`

This function checks if SCP is enabled on the device. If not, the script exits with an error message.

### `validate_interface(connection: ConnectHandler, interface: str) -> Union[bool, None]`

This function validates if the provided interface is present in the output of the 'show ip int brief' command. If the interface is not found, the script exits with an error message.

### `generate_unique_pcap_name(device_name: str) -> str`

This function generates a unique pcap file name based on the device_name and current timestamp.

### `is_enough_space(dir_output: str, required_space: int = 2048) -> bool`

This function checks if there is enough space in the device's flash directory. Returns True if there is enough space and False otherwise.

### `start_capture(connection, interface: str, monitor_session_name: str) -> None`

This function starts the packet capture on the specified interface.

### `stop_capture(connection, monitor_session_name: str) -> None`

This function stops the packet capture.

### `export_capture(connection: ConnectHandler, pcap_file: str, monitor_session_name: str) -> None`

This function exports the packet capture to the device's flash storage.

### `retrieve_capture(connection: ConnectHandler, pcap_file: str) -> None`

This function retrieves the packet capture file using SCP.

### `delete_capture(connection: ConnectHandler, pcap_file: str) -> None`

This function deletes the packet capture file from the device's flash storage.

### `cleanup_capture(connection: ConnectHandler, monitor_session_name: str) -> None`

This function cleans up the capture configuration on the device.

### `contains_pcap_files(output: str) -> bool`

This function checks if the output contains any pcap files. Returns True if pcap files are found, False otherwise.

### `validate(connection: ConnectHandler, interface: str) -> str`

This function validates the connection and provided interface. Returns the device name if validation is successful.

### `packet_capture(device: str, username: str, password: str, interface: str, duration: int, monitor_session_name: str) -> None`

This function performs the packet capture process on a Cisco IOS XE device using Netmiko.

## Future Improvements

    Add support for other network device types, such as Cisco IOS-XR, Cisco NX-OS
    Implement error handling and retries for the network connection and file transfer operations.
    Add filtering options for the packet capture, such as specifying IP addresses, ports, or protocols to be captured.
    Allow users to specify the capture buffer size and other advanced capture settings.

## Example Usage

```python
python3 pcap_getter/get_pcap.py --device 172.200.100.13 --interface GigabitEthernet0/0 --username admin --duration 10
