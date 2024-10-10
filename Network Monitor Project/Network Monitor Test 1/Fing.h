#include <iostream>
#include <stdexcept>
#include <memory>
#include <array>
#include <cstdio>
#include <string>
#include <cstdlib>
#include <sstream>
#include <fstream>
#include <regex>
#include <vector>
#include <cctype>

struct Device {
    std::string ipAddress;   // Stores the device's IP address.
    std::string macAddress;  // Stores the device's MAC address.
    std::string isOnline;    // Stores the device's status: "Online" or "Offline".
    std::string deviceType;  // Stores the type of device: "Known", "Unknown", or "Blocked".
};

// Function to get the current date and time in the format Year-Month-Day_Hour-Minute-Second
// This is used for naming the CSV file with a timestamp
std::string getCurrentDateTime() {
    std::time_t now = std::time(nullptr);  // Get current time
    std::tm localTime;  // Structure to store local time

    // Convert time to local time structure
    localtime_s(&localTime, &now);

    char buf[80];  // Buffer to store the formatted time
    // Format the time as Year-Month-Day_Hour-Minute-Second and store in buffer
    std::strftime(buf, sizeof(buf), "%Y-%m-%d_%H-%M-%S", &localTime);
    return std::string(buf);  // Return the formatted string
}

void exportDevicesToCSV(const std::vector<Device>& devices, const std::string& filename) {
    std::ofstream file(filename);  // Opens or creates the CSV file.

    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;  // Error handling if file fails to open.
        return;
    }

    // Write CSV headers.
    file << "IP Address,MAC Address,Status,Device Type\n";

    // Loop through the devices vector and write each device's details in CSV format.
    for (const auto& device : devices) {
        file << device.ipAddress << "," << device.macAddress << "," << device.isOnline << "," << device.deviceType << "\n";
    }

    file.close();  // Close the file when done.

    std::cout << "Device information has been exported to " << filename << std::endl;  // Inform the user of export success.
}

//--------------------------------------------------------------WINDOWS-----------------------------------------------------------------
bool isFingInstalledWindows() {
    int result = system("where fing >nul 2>nul");  // Executes a system command to check if 'fing' exists.
    return result == 0;  // If the result is 0, 'fing' is installed; otherwise, it's not.
}

bool installFingWindows() {
    std::cout << "Fing is not installed. Installing Fing..." << std::endl;

    int downloadResult = system("curl -O https://www.fing.com/images/uploads/general/windows/fing-latest.exe");  // Downloads Fing.
    if (downloadResult != 0) {
        std::cerr << "Failed to download Fing." << std::endl;
        return false;
    }

    int installResult = system("fing-latest.exe /silent /norestart");  // Silently installs Fing without restarting.
    if (installResult != 0) {
        std::cerr << "Failed to install Fing." << std::endl;
        return false;
    }

    std::cout << "Fing has been successfully installed!" << std::endl;
    return true;
}


std::string runCommandWindows(const char* cmd) {
    std::array<char, 128> buffer;  // Temporary buffer to hold the output from the command.
    std::string result;  // Will store the final result.
    std::shared_ptr<FILE> pipe(_popen(cmd, "r"), _pclose);  // Runs a shell command and pipes the output.

    if (!pipe) throw std::runtime_error("__popen() failed!");  // Error handling if pipe creation fails.

    // Read output from the pipe line-by-line.
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }

    return result;  // Return the output as a string.
}

// Parse Output
std::vector<Device> parseFingOutputWindows(const std::string& output) {
    std::vector<Device> devices;

    std::regex regexPattern(R"((\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(Up|Down)\s+(.*))");  // Regex pattern to capture IP, MAC, Status, and Info.
    std::smatch match;
    std::string::const_iterator searchStart(output.cbegin());  // Start of the output string for regex search.

    while (std::regex_search(searchStart, output.cend(), match, regexPattern)) {
        Device device;  // Create a new device object for each match.
        device.ipAddress = match[1];  // Capture the IP address.
        device.macAddress = match[2];  // Capture the MAC address.
        device.isOnline = (match[3] == "Up") ? "Online" : "Offline";  // Set the status based on "Up" or "Down".

        std::string info = match[4];  // Get the additional info about the device type.
        if (info.find("Known") != std::string::npos) {
            device.deviceType = "Known";
        }
        else if (info.find("Unknown") != std::string::npos) {
            device.deviceType = "Unknown";
        }
        else if (info.find("Blocked") != std::string::npos) {
            device.deviceType = "Blocked";
        }
        else {
            device.deviceType = "Unknown";
        }

        devices.push_back(device);  // Add the device to the list.
        searchStart = match.suffix().first;  // Move to the next match in the output.
    }

    return devices;  // Return the list of devices.
}

// Display Scan Info
void printDeviceTableWindows(const std::vector<Device>& devices) {
    std::cout << "-------------------------------------------------------------" << std::endl;
    std::cout << "| IP Address     | MAC Address       | Status  | Device Type   |" << std::endl;
    std::cout << "-------------------------------------------------------------" << std::endl;

    for (const auto& device : devices) {
        std::cout << "| " << device.ipAddress << " | " << device.macAddress << " | " << device.isOnline << "  | " << device.deviceType << "  |" << std::endl;
    }

    std::cout << "-------------------------------------------------------------" << std::endl;
}

void runFingWindows() {
    if (!isFingInstalledWindows()) {
        if (!installFingWindows()) {
            std::cerr << "Fing installation failed. Exiting..." << std::endl;
            return;
        }
    }

    std::string fingOutput = runCommandWindows("fing -r 1");  // Runs the Fing scan.

    std::vector<Device> devices = parseFingOutputWindows(fingOutput);  // Parses the output.

    printDeviceTableWindows(devices);  // Prints the devices in a table.

    std::string filename = "Fing Scan (" + getCurrentDateTime() + ").csv";  // Creates a filename with the current date and time.

    exportDevicesToCSV(devices, filename);  // Exports the device information to a CSV file.
}

//--------------------------------------------------------------LINUX------------------------------------------------------------------
// Function to check if Fing is installed on a Linux system
bool isFingInstalledLinux() {
    // Executes the 'which' command to check if 'fing' exists in the system's PATH
    // Redirects the output to /dev/null (so it's not displayed to the user)
    int result = system("which fing > /dev/null 2>&1");
    // If the command returns 0, it means Fing is installed; otherwise, it isn't
    return result == 0;
}

// Function to install Fing on a Linux system
void installFingLinux() {
    std::cout << "Fing is not installed. Installing Fing..." << std::endl;

    // Update package lists to ensure the system knows about the latest available software
    system("sudo apt-get update");

    // Install 'curl', a tool for transferring data via URLs, necessary to download Fing
    system("sudo apt-get install -y curl");

    // Use 'curl' to download the latest Fing package from Fing's official website
    system("curl -O https://www.fing.com/images/uploads/general/apt/fing-latest.deb");

    // Install the downloaded .deb package using dpkg
    system("sudo dpkg -i fing-latest.deb");

    // Install any missing dependencies for the package
    system("sudo apt-get install -f");

    // Remove the downloaded .deb package after installation to clean up
    system("rm -f fing-latest.deb");

    std::cout << "Fing has been successfully installed!" << std::endl;
}

// Function to run a shell command on Linux and capture its output
std::string runCommandLinux(const char* cmd) {
    // Creates a buffer to store each line of command output
    std::array<char, 128> buffer;

    // String to store the full result of the command
    std::string result;

    // Open a pipe to execute the shell command, read the output line-by-line
    std::shared_ptr<FILE> pipe(_popen(cmd, "r"), _pclose);

    // If opening the pipe fails, throw an exception
    if (!pipe) throw std::runtime_error("_popen() failed!");

    // Loop to read the command's output from the pipe
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        // Append each line of output to the result string
        result += buffer.data();
    }

    // Return the final accumulated output
    return result;
}

// Function to parse Fing output and extract device information
std::vector<Device> parseFingOutputLinux(const std::string& output) {
    // Vector to store the parsed devices
    std::vector<Device> devices;

    // Regular expression pattern to match IP address, MAC address, status (Up/Down), and additional info
    std::regex regexPattern(R"((\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\S+)\s+(.*))");
    std::smatch match; // To store regex match results
    std::string::const_iterator searchStart(output.cbegin()); // Iterator to traverse the string

    // Loop to search the entire output string using the regex pattern
    while (std::regex_search(searchStart, output.cend(), match, regexPattern)) {
        Device device; // Create a new Device object
        device.ipAddress = match[1]; // Assign the matched IP address
        device.macAddress = match[2]; // Assign the matched MAC address
        device.isOnline = (match[3] == "Up") ? "Up" : "Down"; // Assign the status as either "Up" or "Down"

        // Check the additional information to determine the device type
        std::string info = match[4];
        if (info.find("Known") != std::string::npos) {
            device.deviceType = "Known"; // Device is recognized as "Known"
        }
        else if (info.find("Unknown") != std::string::npos) {
            device.deviceType = "Unknown"; // Device is categorized as "Unknown"
        }
        else if (info.find("Blocked") != std::string::npos) {
            device.deviceType = "Blocked"; // Device is blocked
        }
        else {
            device.deviceType = "Unknown"; // Default to "Unknown" if no match
        }

        // Add the parsed device to the vector
        devices.push_back(device);
        // Move the search start iterator to continue searching the remainder of the string
        searchStart = match.suffix().first;
    }

    // Return the list of parsed devices
    return devices;
}

// Function to print the device table in a formatted way
void printDeviceTableLinux(const std::vector<Device>& devices) {
    // Print table header
    std::cout << "-------------------------------------------------------------" << std::endl;
    std::cout << "| IP Address     | MAC Address       | Status | Device Type   |" << std::endl;
    std::cout << "-------------------------------------------------------------" << std::endl;

    // Loop over each device and print its information
    for (const auto& device : devices) {
        std::cout << "| " << device.ipAddress << " | "
            << device.macAddress << " | "
            << device.isOnline << "   | "
            << device.deviceType << "   |" << std::endl;
    }

    // Print table footer
    std::cout << "-------------------------------------------------------------" << std::endl;
}

// Function to run Fing, parse output, and export results to a CSV
void runFingLinux() {
    // Check if Fing is installed, and if not, install it
    if (!isFingInstalledLinux()) {
        installFingLinux();
    }

    // Run the Fing command to perform a network scan (1 scan)
    std::string fingOutput = runCommandLinux("fing -r 1");

    // Parse the Fing output to extract device information
    std::vector<Device> devices = parseFingOutputLinux(fingOutput);

    // Print the devices in a formatted table
    printDeviceTableLinux(devices);

    // Create a CSV filename using the current date and time (function `getCurrentDateTime()` should be implemented)
    std::string filename = "Fing Scan (" + getCurrentDateTime() + ").csv";

    // Export the parsed devices to a CSV file
    exportDevicesToCSV(devices, filename);
}

//--------------------------------------------------------------MACOS------------------------------------------------------------------
// Function to check if Fing is installed on macOS
bool isFingInstalledMacOS() {
    // Executes the 'which' command to check if 'fing' exists in the system's PATH
    // Redirects output to /dev/null to suppress it
    int result = system("which fing > /dev/null 2>&1");
    // If result is 0, it means Fing is installed, otherwise it's not
    return result == 0;
}

// Function to install Fing on macOS using Homebrew
void installFingMacOS() {
    std::cout << "Fing is not installed. Installing Fing..." << std::endl;

    // Check if Homebrew is installed by using 'which' command
    if (system("which brew > /dev/null 2>&1") != 0) {
        // If Homebrew is not found, install it
        std::cout << "Homebrew is not installed. Installing Homebrew first..." << std::endl;
        // Run the Homebrew installation script
        system("/bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"");
    }

    // Install Fing via Homebrew
    std::cout << "Installing Fing with Homebrew..." << std::endl;
    system("brew install fing");

    std::cout << "Fing has been successfully installed!" << std::endl;
}

// Function to run a Fing scan and capture the output as a string
std::string runFingScanMacOS(const char* cmd) {
    std::array<char, 128> buffer; // Buffer to hold the command output line by line
    std::string result; // String to accumulate the full command output

    // Open a pipe to execute the shell command
    std::shared_ptr<FILE> pipe(_popen(cmd, "r"), _pclose);
    // If opening the pipe fails, throw an exception
    if (!pipe) throw std::runtime_error("_popen() failed!");

    // Read the command output from the pipe until there's no more output
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data(); // Append each line of output to the result string
    }

    return result; // Return the full output
}

// Function to parse Fing scan output and extract device information
std::vector<Device> parseFingOutputMacOS(const std::string& output) {
    std::vector<Device> devices; // Vector to store parsed devices

    // Regular expression pattern to match IP address, MAC address, status, and additional info
    std::regex regexPattern(R"((\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(Up|Down)\s+(.*))");
    std::smatch match; // To store regex match results
    std::string::const_iterator searchStart(output.cbegin()); // Iterator to traverse the output

    // Loop to search through the entire output string using the regex pattern
    while (std::regex_search(searchStart, output.cend(), match, regexPattern)) {
        Device device; // Create a new Device object

        // Extract information from the regex match
        device.ipAddress = match[1]; // Assign the matched IP address
        device.macAddress = match[2]; // Assign the matched MAC address
        device.isOnline = (match[3] == "Up") ? "Up" : "Down"; // Assign the device status (Up/Down)

        // Determine the device type based on the additional info
        std::string info = match[4];
        if (info.find("Known") != std::string::npos) {
            device.deviceType = "Known"; // Device is recognized as "Known"
        }
        else if (info.find("Unknown") != std::string::npos) {
            device.deviceType = "Unknown"; // Device is categorized as "Unknown"
        }
        else if (info.find("Blocked") != std::string::npos) {
            device.deviceType = "Blocked"; // Device is blocked
        }
        else {
            device.deviceType = "Unknown"; // Default to "Unknown" if no match
        }

        devices.push_back(device); // Add the parsed device to the vector

        // Move the iterator to continue searching through the remaining output
        searchStart = match.suffix().first;
    }

    return devices; // Return the list of parsed devices
}

// Function to print a table of device information
void printDeviceTableMacOS(const std::vector<Device>& devices) {
    // Print the table header
    std::cout << "-------------------------------------------------------------" << std::endl;
    std::cout << "| IP Address     | MAC Address       | Status | Device Type   |" << std::endl;
    std::cout << "-------------------------------------------------------------" << std::endl;

    // Loop through each device and print its details
    for (const auto& device : devices) {
        std::cout << "| " << device.ipAddress << " | "
            << device.macAddress << " | "
            << device.isOnline << "   | "
            << device.deviceType << "   |" << std::endl;
    }

    // Print the table footer
    std::cout << "-------------------------------------------------------------" << std::endl;
}

// Main function to run the Fing scan, parse output, and print the results
void runFingMacOS() {
    // Check if Fing is installed, and if not, install it
    if (!isFingInstalledMacOS()) {
        installFingMacOS();
    }

    // Run a Fing network scan (1 round of scan)
    std::string fingOutput = runFingScanMacOS("fing -r 1");

    // Parse the Fing output to extract device information
    std::vector<Device> devices = parseFingOutputMacOS(fingOutput);

    // Print the parsed device information in a formatted table
    printDeviceTableMacOS(devices);

    // Generate a CSV filename with the current date and time (the `getCurrentDateTime` function should be implemented)
    std::string filename = "Fing Scan (" + getCurrentDateTime() + ").csv";

    // Export the device information to a CSV file
    exportDevicesToCSV(devices, filename);
}
