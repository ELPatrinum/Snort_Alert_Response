## Overview
This project is designed to monitor a Snort alert log file and automatically take action based on specific alerts. When a predefined alert is detected, the program extracts the IP address associated with the alert and blocks it using `iptables`.

## Features
- **Real-time Monitoring**: Continuously monitors the Snort alert log file for new entries.
- **IP Blocking**: Automatically blocks IP addresses based on specific alert keywords.
- **Logging**: Logs actions taken, including the date and time of each IP block, to a log file named with the current date and time.

## Prerequisites
- A working installation of Snort with logging enabled.
- C++ compiler (e.g., g++).
- Root privileges for opening the /var.log/snort/alert and modifying `iptables` rules.

## Building the Project
To build the project, use the following command:

```sh
make
```

## Running the Project
Run the compiled program with the following command:

```sh
sudo ./S_A_R
```

## Code Explanation
### Functions
- **`getCurrentDateTime`**: Retrieves the current date and time formatted as `YYYY-MM-DD_HH-MM-SS`.
- **`extractIPAddress`**: Extracts the IP address from a string that includes a port number.
- **`signalHandler`**: Handles the `SIGINT` signal (Ctrl+C) and gracefully exits the program.

### Main Function
- **Initialization**: Registers the signal handler and sets up file paths.
- **File Opening**: Opens the Snort alert log file for reading and a new log file for writing.
- **Monitoring Loop**: Continuously reads new lines from the Snort log file, checks for alert keywords, extracts IP addresses, and blocks them using `iptables`.

## Alert Keywords
The program looks for the following alert keywords in the Snort log:
- `SYN_Flood`
- `UDP_Flood`
- `Excessive_HTTP`
- `Excessive_HTTPS`

## Example Alert Log Entry
An example of an alert log entry that would trigger the program:

```sh
07/16-09:23:39.153899 [**] [1:1000000:0] SYN_Flood detected [**] [Classification: Attempted User Privilege Gain] [Priority: 1] [AppID: HTTP] {TCP} 192.168.1.8:50284 -> 192.168.2.3:80
```

## License
This project is licensed under the MIT License.

---
