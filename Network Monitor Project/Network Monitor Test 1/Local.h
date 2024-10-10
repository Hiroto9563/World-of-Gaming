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
#include <fstream>
#include <cctype>
#include <winsock2.h>    // For Windows socket API
#include <iphlpapi.h>    // For getting IP adapter info
#include <ws2tcpip.h>    // For IP address conversion

#pragma comment(lib, "iphlpapi.lib")  // Link with IP Helper API
#pragma comment(lib, "ws2_32.lib")    // Link with Windows Sockets library

// Function to parse a file containing OUI (Organizationally Unique Identifier) standards
void parseOuiStandards() {
    // Open the input file containing OUI standards
    std::ifstream inFile("D:\\standards-out-ieee.txt");

    // Check if the input file was opened successfully
    if (!inFile.is_open()) {
        std::cerr << "Error opening inFile!" << std::endl;
        return;
    }

    // Create output file streams for 9 files
    std::vector<std::ofstream> outFiles(9);
    for (int i = 0; i < 9; ++i) {
        outFiles[i].open("D:\\OuiStandardsParsed" + std::to_string(i + 1) + ".txt");
        if (!outFiles[i].is_open()) {
            std::cerr << "Error opening outFile" << (i + 1) << "!" << std::endl;
            return;
        }
    }

    std::string line;
    int lineCount = 0;  // To track the current line number
    int fileIndex = 0;  // To track the current output file index

    // Loop through each line of the input file
    while (std::getline(inFile, line)) {
        lineCount++;

        // Skip the first four lines (header information)
        if (lineCount <= 4) {
            continue;
        }

        // Skip empty lines or lines that start with a space
        if (line.empty() || std::isspace(line[0])) {
            continue;
        }

        // Skip lines where the third character is a hyphen (OUI patterns we don't need)
        if (line.length() >= 3 && line[2] == '-') {
            continue;
        }

        // Remove the string "(base 16)" from the line if it exists
        std::string::size_type pos = line.find("(base 16)");
        if (pos != std::string::npos) {
            line.erase(pos, std::string("(base 16)").length());
        }

        // Split the line into the OUI and the company name
        std::stringstream ss(line);
        std::string OUI, company;
        ss >> OUI;  // First token is the OUI
        std::getline(ss, company);  // The rest of the line is the company name

        // Remove leading spaces from the company name
        company.erase(0, company.find_first_not_of(" \t"));

        // Write the OUI and company name to the appropriate output file
        if (!OUI.empty() && !company.empty()) {
            outFiles[fileIndex] << OUI << "  " << company << std::endl;
        }

        // Switch to the next file every 5200 lines
        if ((lineCount - 4) % 5200 == 0) {
            fileIndex = (fileIndex + 1) % 9;
        }
    }

    // Close both the input and output files
    inFile.close();
    for (auto& outFile : outFiles) {
        outFile.close();
    }
}

// Function to calculate the CIDR (number of 1-bits in the subnet mask)
int calculateCIDR(DWORD subnetMask) {
    int cidr = 0;  // Initialize CIDR count
    // Count the number of 1-bits in the subnet mask
    while (subnetMask) {
        cidr += subnetMask & 1;  // Add 1 if the least significant bit is set
        subnetMask >>= 1;        // Shift the subnet mask to the right
    }
    return cidr;  // Return the CIDR value
}

// Function to convert a DWORD (binary representation) IP address to string format
std::string ipToString(DWORD ipAddr) {
    struct in_addr ip;
    ip.s_addr = ipAddr;  // Assign the binary IP address
    char buffer[INET_ADDRSTRLEN];  // Buffer to store the string representation
    inet_ntop(AF_INET, &ip, buffer, sizeof(buffer));  // Convert IP to string format
    return std::string(buffer);  // Return the IP address as a string
}

// Function to calculate the network address from an IP and subnet mask
std::string calculateNetworkAddress(DWORD ip, DWORD subnetMask) {
    DWORD network = ip & subnetMask;  // Perform bitwise AND to get the network address
    return ipToString(network);  // Convert the result to a string
}

// Function to get the current network range in CIDR notation
std::string getNetworkRange() {
    PIP_ADAPTER_INFO adapterInfo;  // Structure to hold adapter information
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);  // Buffer length for adapter info
    adapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);  // Allocate memory for adapter info

    if (adapterInfo == nullptr) {
        std::cerr << "Error allocating memory for adapter info." << std::endl;
        return "";
    }

    // Get the adapter information
    if (GetAdaptersInfo(adapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(adapterInfo);
        adapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);  // Resize buffer if needed
    }

    if (adapterInfo == nullptr) {
        std::cerr << "Error allocating memory for adapter info after resizing." << std::endl;
        return "";
    }

    // Retrieve the adapter information
    if (GetAdaptersInfo(adapterInfo, &ulOutBufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO currentAdapter = adapterInfo;  // Pointer to the current adapter
        // Loop through all available adapters
        while (currentAdapter) {
            // Skip loopback adapters (i.e., local-only adapters)
            if (currentAdapter->Type != MIB_IF_TYPE_LOOPBACK) {
                struct in_addr ipAddr, maskAddr;
                // Convert IP and subnet mask strings to binary format
                if (inet_pton(AF_INET, currentAdapter->IpAddressList.IpAddress.String, &ipAddr) > 0 &&
                    inet_pton(AF_INET, currentAdapter->IpAddressList.IpMask.String, &maskAddr) > 0) {

                    // Calculate the network address using the IP and subnet mask
                    std::string networkAddress = calculateNetworkAddress(ipAddr.s_addr, maskAddr.s_addr);
                    // Calculate the CIDR prefix length from the subnet mask
                    int cidr = calculateCIDR(maskAddr.s_addr);

                    free(adapterInfo);  // Free the adapter info structure
                    return networkAddress + "/" + std::to_string(cidr);  // Return network range
                }
            }
            currentAdapter = currentAdapter->Next;  // Move to the next adapter
        }
    }

    free(adapterInfo);  // Free the memory for adapter info
    return "Unable to get network range.";  // Return error if no valid adapter was found
}

// Function to validate whether the given network range is in valid CIDR notation
bool validNetworkRange(const std::string& networkRange) {
    // Regular expression for validating CIDR notation (e.g., 192.168.1.0/24)
    std::regex cidrRegex(R"(^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/(3[0-2]|[12]?[0-9])$)");
    return std::regex_match(networkRange, cidrRegex);  // Return true if the network range matches the regex
}

// Function to check if a host is alive using the 'ping' command
bool isHostAlive(const std::string& ip) {
    // Construct the ping command with a 1-second timeout and discard output
    std::string command = "ping -n 1 -w 1000 " + ip + " > nul";
    int result = system(command.c_str());  // Execute the ping command
    return (result == 0);  // Return true if the ping was successful
}

// Function to retrieve the MAC address associated with an IP address using the 'arp' command
std::string getMacAddress(const std::string& ip) {
    // Construct the arp command for the given IP
    std::string command = "arp -a " + ip;
    char buffer[128];      // Buffer to store command output
    std::string result = "";  // To accumulate the output of the command

    // Open a pipe to execute the arp command and read its output
    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) return "Error";  // Return error if pipe fails to open

    // Read the command output into the result string
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    _pclose(pipe);  // Close the pipe

    // Parse the arp output to find the MAC address for the specific IP
    std::stringstream ss(result);
    std::string line;

    // Iterate through each line of the command output
    while (std::getline(ss, line)) {
        // Look for the line containing the target IP
        if (line.find(ip) != std::string::npos) {
            std::istringstream iss(line);
            std::string ipAddr, macAddr, type;

            // Extract the IP, MAC address, and type from the line
            iss >> ipAddr >> macAddr >> type;

            // If the IP matches the target IP, return the MAC address
            if (ipAddr == ip) {
                return macAddr;
            }
        }
    }
    // If no MAC address found, return a not-found message
    return "MAC not found";
}

// Function to scan a range of IP addresses and print their MAC addresses if alive
void scanIPAddresses() {
    // Prompt the user for the base IP address (e.g., 192.168.1.)
    //std::cout << "What is your Base IP Address? ";
    std::string baseIP;
    //std::cin >> baseIP;

    baseIP = getNetworkRange();

    int start = 1, end = 254;  // Set the IP range to scan (1-254)
    std::cout << "Scanning IP range: " << baseIP << start << " to " << baseIP << end << ".\n";
    std::cout << "             IP Address       MAC Address\n";
    std::cout << "********************************************************\n";

    // Loop through the IP range and check if each IP is alive
    for (int i = start; i <= end; i++) {
        // Construct the current IP by appending the host number to the base IP
        std::string currentIP = baseIP + std::to_string(i);

        // Check if the host at this IP is alive
        if (isHostAlive(currentIP)) {
            // If alive, retrieve the MAC address for the host
            std::string macAddress = getMacAddress(currentIP);

            // Add padding to the IP string for alignment in the output
            if (currentIP.length() < 11) { currentIP.insert(11, "=="); }
            if (currentIP.length() >= 11 && currentIP.length() < 13) { currentIP.insert(12, " "); }

            // Format and print the result (IP and MAC address)
            std::string Output = "Host is up: " + currentIP + macAddress + "\n";
            std::cout << Output.insert(25, " | ");
        }
    }
    std::cout << "Scan Complete." << std::endl;
}