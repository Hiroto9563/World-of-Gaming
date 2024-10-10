#include "net-snmp-5.9.4\\win32\\net-snmp\\net-snmp-config.h"
#include "net-snmp-5.9.4\\include\\net-snmp\\net-snmp-includes.h"

struct macTableEntry {
    std::string macAddress;
    std::string portNumber;
    std::string vlanID;
    std::string ageingTime;
    std::string dynamicOrStatic;
};

//-------------------------------------------------------------Windows-----------------------------------------------------------------
// Function to convert MAC address in OID format to human-readable format
std::string oidToMacAddress(oid* macOid, size_t length) {
    std::ostringstream macStream;
    for (size_t i = 0; i < length; ++i) {
        macStream << std::hex << std::setw(2) << std::setfill('0') << macOid[i];
        if (i != length - 1)
            macStream << ":";
    }
    return macStream.str();
}

// Function to query SNMP for MAC address table
std::vector<macTableEntry> queryMacTable(const std::string& ipAddress, const std::string& community) {
    std::vector<macTableEntry> macTable;
    struct snmp_session session, * ss;
    struct snmp_pdu* pdu;
    struct snmp_pdu* response;
    struct variable_list* vars;
    int status;

    // Initialize SNMP session
    snmp_sess_init(&session);
    session.peername = strdup(ipAddress.c_str());
    session.version = SNMP_VERSION_2c;
    session.community = (u_char*)community.c_str();
    session.community_len = community.length();

    // Open SNMP session
    ss = snmp_open(&session);
    if (!ss) {
        snmp_perror("snmp_open");
        return macTable;
    }

    // Create SNMP PDU to request MAC address table
    pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
    pdu->non_repeaters = 0;
    pdu->max_repetitions = 10;

    // OIDs for MAC addresses, port numbers, VLAN ID, ageing time, and dynamic/static status
    oid macOid[] = { 1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 1 };  // OID for MAC addresses
    oid portOid[] = { 1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2 }; // OID for port numbers
    oid ageingOid[] = { 1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 3 }; // OID for ageing time
    oid vlanOid[] = { 1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 2, 1, 3 }; // OID for VLAN ID

    // Add OIDs for querying
    snmp_add_null_var(pdu, macOid, sizeof(macOid) / sizeof(oid));
    snmp_add_null_var(pdu, portOid, sizeof(portOid) / sizeof(oid));
    snmp_add_null_var(pdu, ageingOid, sizeof(ageingOid) / sizeof(oid));
    snmp_add_null_var(pdu, vlanOid, sizeof(vlanOid) / sizeof(oid));

    // Perform the SNMP query
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
        // Process the response
        for (vars = response->variables; vars; vars = vars->next_variable) {
            macTableEntry entry;

            // Get MAC address
            if (memcmp(vars->name, macOid, sizeof(macOid)) == 0) {
                entry.macAddress = oidToMacAddress(vars->name + vars->name_length - 6, 6);

                // Get port number (next variable)
                vars = vars->next_variable;
                entry.portNumber = std::to_string(*vars->val.integer);

                // Get VLAN ID (next variable)
                vars = vars->next_variable;
                entry.vlanID = std::to_string(*vars->val.integer);

                // Get Ageing time (next variable)
                vars = vars->next_variable;
                entry.ageingTime = std::to_string(*vars->val.integer) + " seconds";

                // Determine if the entry is dynamic or static
                entry.dynamicOrStatic = (*vars->val.integer > 0) ? "Dynamic" : "Static";

                macTable.push_back(entry);
            }
        }
    }
    else {
        if (status == STAT_SUCCESS)
            std::cerr << "Error in SNMP response: " << response->errstat << std::endl;
        else
            snmp_perror("snmp_synch_response");
    }

    // Clean up
    if (response)
        snmp_free_pdu(response);
    snmp_close(ss);

    return macTable;
}
// std::vector<macTableEntry> queryMacTableWindows() {
std::vector<macTableEntry> macTable;
FILE* pipe = _popen("arp -a", "r");  // Windows arp command
if (!pipe) {
    std::cerr << "Error opening arp command!" << std::endl;
    return macTable;
}

char buffer[128];
while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
    std::string line(buffer);
    std::stringstream ss(line);
    macTableEntry entry;

    std::string ipAddr, macAddr, type;
    ss >> ipAddr >> macAddr >> type;
    // Add information to the macTableEntry structure
    entry.macAddress = macAddr;
    entry.portNumber = "N/A";  // ARP doesn't give port information
    entry.vlanID = "N/A";
    entry.ageingTime = "N/A";
    entry.dynamicOrStatic = "Dynamic";  // ARP entries are usually dynamic

    macTable.push_back(entry);
}
_pclose(pipe);
return macTable;
}

//--------------------------------------------------------------LINUX------------------------------------------------------------------
// std::vector<macTableEntry> queryMacTableLinux() {
std::vector<macTableEntry> macTable;
FILE* pipe = popen("bridge fdb show", "r");  // Use bridge command on Linux
if (!pipe) {
    std::cerr << "Error opening pipe for bridge fdb show!" << std::endl;
    return macTable;
}

char buffer[256];
while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
    std::string line(buffer);
    std::stringstream ss(line);
    macTableEntry entry;
    ss >> entry.macAddress >> entry.portNumber >> entry.vlanID >> entry.ageingTime;
    // Populate whether it's dynamic or static based on the remaining fields
    entry.dynamicOrStatic = (line.find("permanent") != std::string::npos) ? "Static" : "Dynamic";
    macTable.push_back(entry);
}
pclose(pipe);
return macTable;
}

//--------------------------------------------------------------MACOS------------------------------------------------------------------
//--------------------------------------------------------------Other------------------------------------------------------------------
void populateMacTable(std::vector<macTableEntry>& macTable) {
    macTable.clear();  // Clear existing entries

#ifdef _WIN32
    // Call the Windows-specific function
    std::vector<macTableEntry> windowsMacTable = queryMacTableWindows();
    macTable.insert(macTable.end(), windowsMacTable.begin(), windowsMacTable.end());
#elif __linux__
    // Call the Linux-specific function
    std::vector<macTableEntry> linuxMacTable = queryMacTableLinux();
    macTable.insert(macTable.end(), linuxMacTable.begin(), linuxMacTable.end());
#elif __APPLE__
    // Call macOS-specific function
    std::vector<macTableEntry> macOsMacTable = queryMacTableMacOS();
    macTable.insert(macTable.end(), macOsMacTable.begin(), macOsMacTable.end());
#else
    std::cerr << "Unsupported platform!" << std::endl;
#endif

    if (macTable.empty()) {
        std::cerr << "No MAC entries found or an error occurred while fetching the MAC table." << std::endl;
    }
}

// Function to print the MAC address table
void printMacTable(const std::vector<macTableEntry>& macTable) {
    std::cout << "----------------------------------------------------------------------------------" << std::endl;
    std::cout << "| MAC Address         | Port Number  | VLAN ID | Ageing Time   | Static/Dynamic |" << std::endl;
    std::cout << "----------------------------------------------------------------------------------" << std::endl;

    for (const auto& entry : macTable) {
        std::cout << "| " << std::setw(17) << entry.macAddress
            << " | " << std::setw(12) << entry.portNumber
            << " | " << std::setw(7) << entry.vlanID
            << " | " << std::setw(12) << entry.ageingTime
            << " | " << std::setw(15) << entry.dynamicOrStatic
            << " |" << std::endl;
    }

    std::cout << "----------------------------------------------------------------------------------" << std::endl;
}