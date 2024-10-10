#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>
#include <map>
#include <regex>
#include <cstdlib>
#include <string>
#include <iomanip>
#include <bitset>

// Function to check if Nmap is installed by running the 'nmap --version' command
// If Nmap is installed, the command will succeed (return 0), otherwise it will fail
bool isNmapInstalled() {
    // Run the Nmap version command and suppress output (nul) and error (2>&1)
    return system("nmap --version >nul 2>&1") == 0;
}

// Function to prompt the user to install Nmap
// If Nmap is not installed, it prints a message and opens the download page in the browser
void promptNmapInstallation() {
    std::cout << "Nmap is not installed. Please download and install it from https://nmap.org/download.html." << std::endl;
    system("start https://nmap.org/download.html");  // Opens the Nmap download page in default browser
}

// Function to run an Nmap scan on the provided network range (e.g., 192.168.1.0/24)
// The scan results are saved in a file called 'nmap_output.txt'
void runNmapScan(const std::string& network) {
    // Construct the Nmap command for scanning the network and saving output to a file
    std::string cmd = "nmap -sn " + network + " -oN nmap_output.txt";

    // Run the command, and if it fails (non-zero return), display an error message
    if (system(cmd.c_str()) != 0) {
        std::cerr << "Nmap scan failed. Please ensure Nmap is installed and you have the required permissions." << std::endl;
        return;
    }
}

// Function to classify an IP address based on whether it is in the whitelist, blacklist, or unknown
// It returns "Whitelisted", "Blacklisted", or "Unknown"
std::string classifyIPAddress(const std::string& ip, const std::map<std::string, std::string>& whitelist, const std::map<std::string, std::string>& blacklist) {
    // If the IP is in the whitelist, return "Whitelisted"
    if (whitelist.find(ip) != whitelist.end()) {
        return "Whitelisted";
    }
    // If the IP is in the blacklist, return "Blacklisted"
    else if (blacklist.find(ip) != blacklist.end()) {
        return "Blacklisted";
    }
    // If the IP is not in either, return "Unknown"
    return "Unknown";
}

// Function to parse the Nmap output file 'nmap_output.txt' and generate a CSV file
// The CSV includes IP addresses, MAC addresses, their online status, and classification
void parseNmapOutput(const std::string& filename, const std::map<std::string, std::string>& whitelist, const std::map<std::string, std::string>& blacklist) {
    // Open the Nmap output file for reading
    std::ifstream infile("nmap_output.txt");
    if (!infile.is_open()) {
        // If the file cannot be opened, display an error message and return
        std::cerr << "Failed to open nmap_output.txt. Ensure the Nmap scan completed successfully." << std::endl;
        return;
    }

    // Open a CSV file for writing the results
    std::ofstream csvfile(filename);
    if (!csvfile.is_open()) {
        // If the CSV file cannot be created, display an error message, close the input file, and return
        std::cerr << "Failed to create CSV file: " << filename << std::endl;
        infile.close();
        return;
    }

    std::string line;          // Variable to store each line of Nmap output
    std::string ip_address;    // Variable to store the current IP address
    std::string mac_address;   // Variable to store the MAC address
    bool isOnline = false;     // Flag to track if the current host is online

    // Write the CSV header
    csvfile << "IP Address,MAC Address,Is Online,Classification" << std::endl;

    // Loop through each line of the Nmap output file
    while (std::getline(infile, line)) {
        // If the line contains the string "Nmap scan report for", extract the IP address
        if (line.find("Nmap scan report for") != std::string::npos) {
            isOnline = true;  // Mark the host as online
            std::istringstream iss(line);
            std::string tmp;
            iss >> tmp >> tmp >> ip_address;  // Extract the IP address from the line
        }
        // If the line contains "MAC Address:", extract the MAC address
        else if (line.find("MAC Address:") != std::string::npos) {
            std::istringstream iss(line);
            std::string tmp;
            iss >> tmp >> tmp >> mac_address;  // Extract the MAC address from the line
        }
        // If an empty line is encountered, process the current host (IP + MAC)
        else if (line.empty() && isOnline) {
            // Classify the IP address as whitelisted, blacklisted, or unknown
            std::string classification = classifyIPAddress(ip_address, whitelist, blacklist);
            // Print the scan results to the console and write them to the CSV file
            std::cout << ip_address << " | " << mac_address << " | Yes | " << classification << std::endl;
            csvfile << ip_address << "," << mac_address << ",Yes," << classification << std::endl;
            isOnline = false;  // Reset the online flag for the next host
        }
    }

    // Close the input and output files
    infile.close();
    csvfile.close();
}

// Function to run the full Nmap scanning process on a Windows machine
void runNmapWindows() {
    // Define a whitelist and blacklist of IP addresses for classification
    std::map<std::string, std::string> whitelist = {
        {"192.168.1.1", "Router"},
        {"192.168.1.2", "Printer"}
    };
    std::map<std::string, std::string> blacklist = {
        {"192.168.1.100", "Suspicious Device"}
    };

    // Check if Nmap is installed on the system
    if (!isNmapInstalled()) {
        promptNmapInstallation();  // If not installed, prompt user to install Nmap
        return;
    }

    // Get the network range using a separate function (not shown here)
    std::string network = getNetworkRange();
    if (!network.empty()) {
        // If the network range was successfully determined, run the Nmap scan
        std::cout << "Network range: " << network << std::endl;
        runNmapScan(network);
    }
    else {
        // If unable to determine the network range, prompt the user to enter it manually
        std::cerr << "Failed to determine network range." << std::endl;
        char answer;
        int attempts = 0;
        while (true) {
            std::cout << "Would you like to manually enter the network range (Y/N)? ";
            std::cin >> answer;

            if (answer == 'Y' || answer == 'y') {
                // Prompt the user to enter the network range (e.g., 192.168.1.0/24)
                std::cout << "What is your network range (i.e. 192.168.1.0/24)? ";
                std::cin >> network;

                // Validate the network range using a regular expression (function not shown)
                if (validNetworkRange(network)) {
                    runNmapScan(network);  // If valid, run the Nmap scan
                    break;
                }
                else {
                    std::cerr << "Invalid network range. Please try again." << std::endl;
                }

                // Limit the number of invalid attempts
                attempts++;
                if (attempts >= 3) {
                    std::cerr << "Too many invalid attempts. Exiting." << std::endl;
                    break;
                }
            }
            else if (answer == 'N' || answer == 'n') {
                break;  // Exit if the user does not want to manually enter the network range
            }
        }
    }

    // Parse the Nmap output and generate a CSV file with the results
    std::string csv_filename = "Nmap_scan_" + getCurrentDateTime() + ".csv";
    parseNmapOutput(csv_filename, whitelist, blacklist);

    // Notify the user where the CSV results are saved
    std::cout << "Nmap scan results saved to " << csv_filename << std::endl;
}

//--------------------------------------------------------------LINUX------------------------------------------------------------------
// Function to check if Nmap is installed by running the 'nmap --version' command
// If Nmap is installed, the command will succeed (return 0), otherwise it will fail
bool isNmapInstalledLinux() {
    // On Linux, 'nmap --version' returns 0 if Nmap is installed; suppress the output using /dev/null
    return system("nmap --version > /dev/null 2>&1") == 0;
}

// Function to prompt the user to install Nmap
// If Nmap is not installed, it prints a message suggesting the installation command
void promptNmapInstallationLinux() {
    std::cout << "Nmap is not installed. Please install it using your package manager.\n";
    std::cout << "For example, on Ubuntu or Debian: sudo apt install nmap\n";
    std::cout << "For Fedora or RHEL: sudo dnf install nmap\n";
}

// Function to run an Nmap scan on the provided network range (e.g., 192.168.1.0/24)
// The scan results are saved in a file called 'nmap_output.txt'
void runNmapScanLinux(const std::string& network) {
    // Construct the Nmap command for scanning the network and saving output to a file
    std::string cmd = "nmap -sn " + network + " -oN nmap_output.txt";

    // Run the command, and if it fails (non-zero return), display an error message
    if (system(cmd.c_str()) != 0) {
        std::cerr << "Nmap scan failed. Please ensure Nmap is installed and you have the required permissions." << std::endl;
        return;
    }
}

// Function to get the current date and time in the format Year-Month-Day_Hour-Minute-Second
// This is used for naming the CSV file with a timestamp
std::string getCurrentDateTimeLinux() {
    std::time_t now = std::time(nullptr);  // Get current time
    std::tm localTime;  // Structure to store local time

#ifdef _WIN32  // Windows
    localtime_s(&localTime, &now);  // Use localtime_s for Windows
#else  // Linux/Unix (POSIX)
    localtime_r(&now, &localTime);  // Use localtime_r for POSIX systems
#endif

    char buf[80];  // Buffer to store the formatted time
    std::strftime(buf, sizeof(buf), "%Y-%m-%d_%H-%M-%S", &localTime);  // Format time
    return std::string(buf);  // Return the formatted string
}

// Function to classify an IP address based on whether it is in the whitelist, blacklist, or unknown
// It returns "Whitelisted", "Blacklisted", or "Unknown"
std::string classifyIPAddressLinux(const std::string& ip, const std::map<std::string, std::string>& whitelist, const std::map<std::string, std::string>& blacklist) {
    // If the IP is in the whitelist, return "Whitelisted"
    if (whitelist.find(ip) != whitelist.end()) {
        return "Whitelisted";
    }
    // If the IP is in the blacklist, return "Blacklisted"
    else if (blacklist.find(ip) != blacklist.end()) {
        return "Blacklisted";
    }
    // If the IP is not in either, return "Unknown"
    return "Unknown";
}

// Function to parse the Nmap output file 'nmap_output.txt' and generate a CSV file
// The CSV includes IP addresses, MAC addresses, their online status, and classification
void parseNmapOutputLinux(const std::string& filename, const std::map<std::string, std::string>& whitelist, const std::map<std::string, std::string>& blacklist) {
    // Open the Nmap output file for reading
    std::ifstream infile("nmap_output.txt");
    if (!infile.is_open()) {
        // If the file cannot be opened, display an error message and return
        std::cerr << "Failed to open nmap_output.txt. Ensure the Nmap scan completed successfully." << std::endl;
        return;
    }

    // Open a CSV file for writing the results
    std::ofstream csvfile(filename);
    if (!csvfile.is_open()) {
        // If the CSV file cannot be created, display an error message, close the input file, and return
        std::cerr << "Failed to create CSV file: " << filename << std::endl;
        infile.close();
        return;
    }

    std::string line;          // Variable to store each line of Nmap output
    std::string ip_address;    // Variable to store the current IP address
    std::string mac_address;   // Variable to store the MAC address
    bool isOnline = false;     // Flag to track if the current host is online

    // Write the CSV header
    csvfile << "IP Address,MAC Address,Is Online,Classification" << std::endl;

    // Loop through each line of the Nmap output file
    while (std::getline(infile, line)) {
        // If the line contains the string "Nmap scan report for", extract the IP address
        if (line.find("Nmap scan report for") != std::string::npos) {
            isOnline = true;  // Mark the host as online
            std::istringstream iss(line);
            std::string tmp;
            iss >> tmp >> tmp >> ip_address;  // Extract the IP address from the line
        }
        // If the line contains "MAC Address:", extract the MAC address
        else if (line.find("MAC Address:") != std::string::npos) {
            std::istringstream iss(line);
            std::string tmp;
            iss >> tmp >> tmp >> mac_address;  // Extract the MAC address from the line
        }
        // If an empty line is encountered, process the current host (IP + MAC)
        else if (line.empty() && isOnline) {
            // Classify the IP address as whitelisted, blacklisted, or unknown
            std::string classification = classifyIPAddress(ip_address, whitelist, blacklist);
            // Print the scan results to the console and write them to the CSV file
            std::cout << ip_address << " | " << mac_address << " | Yes | " << classification << std::endl;
            csvfile << ip_address << "," << mac_address << ",Yes," << classification << std::endl;
            isOnline = false;  // Reset the online flag for the next host
        }
    }

    // Close the input and output files
    infile.close();
    csvfile.close();
}

bool validNetworkRangeLinux(const std::string& network) {
    // Regular expression for validating IP ranges in CIDR notation (e.g., 192.168.1.0/24)
    std::regex cidr_pattern(R"((\d{1,3}\.){3}\d{1,3}/\d{1,2})");
    return std::regex_match(network, cidr_pattern);
}

// Function to execute a shell command and capture its output
std::string execCommand(const std::string& command) {
    std::array<char, 128> buffer;
    std::string result;
    std::shared_ptr<FILE> pipe(_popen(command.c_str(), "r"), _pclose);
    if (!pipe) {
        throw std::runtime_error("_popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

// Function to extract the network range in CIDR format from 'ip a' command output
std::string getNetworkRangeLinux() {
    try {
        // Execute the 'ip a' command and capture its output
        std::string ipOutput = execCommand("ip a");

        // Regular expression to match IP addresses and subnet masks in CIDR notation
        std::regex ip_regex(R"((\d{1,3}\.){3}\d{1,3}/\d{1,2})");

        std::smatch match;

        // Search for the first match (typically the primary network interface)
        if (std::regex_search(ipOutput, match, ip_regex)) {
            return match.str();  // Return the first found IP range
        }
        else {
            std::cerr << "No valid network range found." << std::endl;
            return "";
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error getting network range: " << e.what() << std::endl;
        return "";
    }
}

// Function to run the full Nmap scanning process on a Linux machine
void runNmapLinux() {
    // Define a whitelist and blacklist of IP addresses for classification
    std::map<std::string, std::string> whitelist = {
        {"192.168.1.1", "Router"},
        {"192.168.1.2", "Printer"}
    };
    std::map<std::string, std::string> blacklist = {
        {"192.168.1.100", "Suspicious Device"}
    };

    // Check if Nmap is installed on the system
    if (!isNmapInstalledLinux()) {
        promptNmapInstallationLinux();  // If not installed, prompt user to install Nmap
        return;
    }

    // Get the network range using a separate function (not shown here)
    std::string network = getNetworkRangeLinux();
    if (!network.empty()) {
        // If the network range was successfully determined, run the Nmap scan
        std::cout << "Network range: " << network << std::endl;
        runNmapScanLinux(network);
    }
    else {
        // If unable to determine the network range, prompt the user to enter it manually
        std::cerr << "Failed to determine network range." << std::endl;
        char answer;
        int attempts = 0;
        while (true) {
            std::cout << "Would you like to manually enter the network range (Y/N)? ";
            std::cin >> answer;

            if (answer == 'Y' || answer == 'y') {
                // Prompt the user to enter the network range (e.g., 192.168.1.0/24)
                std::cout << "What is your network range (i.e. 192.168.1.0/24)? ";
                std::cin >> network;

                // Validate the network range using a regular expression (function not shown)
                if (validNetworkRangeLinux(network)) {
                    runNmapScanLinux(network);  // If valid, run the Nmap scan
                    break;
                }
                else {
                    std::cerr << "Invalid network range. Please try again." << std::endl;
                }

                // Limit the number of invalid attempts
                attempts++;
                if (attempts >= 3) {
                    std::cerr << "Too many invalid attempts. Exiting." << std::endl;
                    break;
                }
            }
            else if (answer == 'N' || answer == 'n') {
                break;
            }
        }
    }

    // After the scan is complete, parse the output and generate a CSV file
    std::string csv_filename = "Nmap_scan_" + getCurrentDateTimeLinux() + ".csv";
    parseNmapOutputLinux(csv_filename, whitelist, blacklist);

    // Notify the user where the CSV results are saved
    std::cout << "Nmap scan results saved to " << csv_filename << std::endl;
}

//--------------------------------------------------------------MACOS------------------------------------------------------------------
// Function to check if Nmap is installed by running the 'nmap --version' command
// If Nmap is installed, the command will succeed (return 0), otherwise it will fail
bool isNmapInstalledMacOS() {
    // On macOS, 'nmap --version' returns 0 if Nmap is installed; suppress the output using /dev/null
    return system("nmap --version > /dev/null 2>&1") == 0;
}

// Function to prompt the user to install Nmap
// If Nmap is not installed, it prints a message suggesting the installation command
void promptNmapInstallationMacOS() {
    std::cout << "Nmap is not installed. Please install it using Homebrew or another package manager.\n";
    std::cout << "For example, you can install it using Homebrew with the command: brew install nmap\n";
}

// Function to run an Nmap scan on the provided network range (e.g., 192.168.1.0/24)
// The scan results are saved in a file called 'nmap_output.txt'
void runNmapScanMacOS(const std::string& network) {
    // Construct the Nmap command for scanning the network and saving output to a file
    std::string cmd = "nmap -sn " + network + " -oN nmap_output.txt";

    // Run the command, and if it fails (non-zero return), display an error message
    if (system(cmd.c_str()) != 0) {
        std::cerr << "Nmap scan failed. Please ensure Nmap is installed and you have the required permissions." << std::endl;
        return;
    }
}

// Function to get the current date and time in the format Year-Month-Day_Hour-Minute-Second
// This is used for naming the CSV file with a timestamp
std::string getCurrentDateTimeMacOS() {
    std::time_t now = std::time(nullptr);  // Get current time
    std::tm localTime;  // Structure to store local time

    // Use localtime_s on Windows, but use localtime_r on POSIX systems (like macOS)
#ifdef _WIN32
    localtime_s(&localTime, &now);  // Thread-safe conversion on Windows
#else
    localtime_r(&now, &localTime);   // Thread-safe conversion on POSIX (macOS/Linux)
#endif

    char buf[80];  // Buffer to store the formatted time
    // Format the time as Year-Month-Day_Hour-Minute-Second and store in buffer
    std::strftime(buf, sizeof(buf), "%Y-%m-%d_%H-%M-%S", &localTime);
    return std::string(buf);  // Return the formatted string
}

// Function to classify an IP address based on whether it is in the whitelist, blacklist, or unknown
// It returns "Whitelisted", "Blacklisted", or "Unknown"
std::string classifyIPAddressMacOS(const std::string& ip, const std::map<std::string, std::string>& whitelist, const std::map<std::string, std::string>& blacklist) {
    // If the IP is in the whitelist, return "Whitelisted"
    if (whitelist.find(ip) != whitelist.end()) {
        return "Whitelisted";
    }
    // If the IP is in the blacklist, return "Blacklisted"
    else if (blacklist.find(ip) != blacklist.end()) {
        return "Blacklisted";
    }
    // If the IP is not in either, return "Unknown"
    return "Unknown";
}

// Function to parse the Nmap output file 'nmap_output.txt' and generate a CSV file
// The CSV includes IP addresses, MAC addresses, their online status, and classification
void parseNmapOutputMacOS(const std::string& filename, const std::map<std::string, std::string>& whitelist, const std::map<std::string, std::string>& blacklist) {
    // Open the Nmap output file for reading
    std::ifstream infile("nmap_output.txt");
    if (!infile.is_open()) {
        // If the file cannot be opened, display an error message and return
        std::cerr << "Failed to open nmap_output.txt. Ensure the Nmap scan completed successfully." << std::endl;
        return;
    }

    // Open a CSV file for writing the results
    std::ofstream csvfile(filename);
    if (!csvfile.is_open()) {
        // If the CSV file cannot be created, display an error message, close the input file, and return
        std::cerr << "Failed to create CSV file: " << filename << std::endl;
        infile.close();
        return;
    }

    std::string line;          // Variable to store each line of Nmap output
    std::string ip_address;    // Variable to store the current IP address
    std::string mac_address;   // Variable to store the MAC address
    bool isOnline = false;     // Flag to track if the current host is online

    // Write the CSV header
    csvfile << "IP Address,MAC Address,Is Online,Classification" << std::endl;

    // Loop through each line of the Nmap output file
    while (std::getline(infile, line)) {
        // If the line contains the string "Nmap scan report for", extract the IP address
        if (line.find("Nmap scan report for") != std::string::npos) {
            isOnline = true;  // Mark the host as online
            std::istringstream iss(line);
            std::string tmp;
            iss >> tmp >> tmp >> ip_address;  // Extract the IP address from the line
        }
        // If the line contains "MAC Address:", extract the MAC address
        else if (line.find("MAC Address:") != std::string::npos) {
            std::istringstream iss(line);
            std::string tmp;
            iss >> tmp >> tmp >> mac_address;  // Extract the MAC address from the line
        }
        // If an empty line is encountered, process the current host (IP + MAC)
        else if (line.empty() && isOnline) {
            // Classify the IP address as whitelisted, blacklisted, or unknown
            std::string classification = classifyIPAddressMacOS(ip_address, whitelist, blacklist);
            // Print the scan results to the console and write them to the CSV file
            std::cout << ip_address << " | " << mac_address << " | Yes | " << classification << std::endl;
            csvfile << ip_address << "," << mac_address << ",Yes," << classification << std::endl;
            isOnline = false;  // Reset the online flag for the next host
        }
    }

    // Close the input and output files
    infile.close();
    csvfile.close();
}

std::string getNetworkRangeMacOS() {
    // Run the 'ifconfig' command and capture the output
    std::string ifconfigOutput = execCommand("ifconfig");

    // Regular expression to capture IP addresses and subnet masks
    std::regex ip_regex(R"((\d{1,3}\.){3}\d{1,3})");  // Match the IP address part
    std::regex mask_regex(R"((0|128|192|224|240|248|252|254|255)(\.0){0,3})");  // Match subnet masks

    std::smatch match;
    std::string ip, mask;

    // Find the first IP address in the output
    if (std::regex_search(ifconfigOutput, match, ip_regex)) {
        ip = match.str();
    }
    else {
        std::cerr << "No valid IP address found." << std::endl;
        return "";
    }

    // Find the first subnet mask in the output
    if (std::regex_search(ifconfigOutput, match, mask_regex)) {
        mask = match.str();
    }
    else {
        std::cerr << "No valid subnet mask found." << std::endl;
        return "";
    }

    // Convert subnet mask to CIDR notation
    int cidr = 0;
    std::istringstream maskStream(mask);
    std::string octet;
    while (std::getline(maskStream, octet, '.')) {
        cidr += std::bitset<8>(std::stoi(octet)).count();  // Count the number of set bits
    }

    // Return the IP address in CIDR format
    return ip + "/" + std::to_string(cidr);
}

bool validNetworkRangeMacOS(const std::string& network) {
    // Regular expression for validating IP ranges in CIDR notation (e.g., 192.168.1.0/24)
    std::regex cidr_pattern(R"((\d{1,3}\.){3}\d{1,3}/\d{1,2})");
    return std::regex_match(network, cidr_pattern);
}

// Function to run the full Nmap scanning process on a macOS machine
void runNmapMacOS() {
    // Define a whitelist and blacklist of IP addresses for classification
    std::map<std::string, std::string> whitelist = {
        {"192.168.1.1", "Router"},
        {"192.168.1.2", "Printer"}
    };
    std::map<std::string, std::string> blacklist = {
        {"192.168.1.100", "Suspicious Device"}
    };

    // Check if Nmap is installed on the system
    if (!isNmapInstalledMacOS()) {
        promptNmapInstallationMacOS();  // If not installed, prompt user to install Nmap
        return;
    }

    // Get the network range using a separate function (not shown here)
    std::string network = getNetworkRangeMacOS();
    if (!network.empty()) {
        // If the network range was successfully determined, run the Nmap scan
        std::cout << "Network range: " << network << std::endl;
        runNmapScanMacOS(network);
    }
    else {
        // If unable to determine the network range, prompt the user to enter it manually
        std::cerr << "Failed to determine network range." << std::endl;
        char answer;
        int attempts = 0;
        while (true) {
            std::cout << "Would you like to manually enter the network range (Y/N)? ";
            std::cin >> answer;

            if (answer == 'Y' || answer == 'y') {
                // Prompt the user to enter the network range (e.g., 192.168.1.0/24)
                std::cout << "What is your network range (i.e. 192.168.1.0/24)? ";
                std::cin >> network;

                // Validate the network range using a regular expression (function not shown)
                if (validNetworkRangeMacOS(network)) {
                    runNmapScanMacOS(network);  // If valid, run the Nmap scan
                    break;
                }
                else {
                    std::cerr << "Invalid network range. Please try again." << std::endl;
                }

                // Limit the number of invalid attempts
                attempts++;
                if (attempts >= 3) {
                    std::cerr << "Too many invalid attempts. Exiting." << std::endl;
                    break;
                }
            }
            else if (answer == 'N' || answer == 'n') {
                break;  // Exit the loop if the user chooses not to enter a network range
            }
        }
    }

    // After the scan is complete, parse the output and generate a CSV file
    std::string csv_filename = "Nmap_scan_" + getCurrentDateTime() + ".csv";
    parseNmapOutputMacOS(csv_filename, whitelist, blacklist);

    // Notify the user where the CSV results are saved
    std::cout << "Nmap scan results saved to " << csv_filename << std::endl;
}