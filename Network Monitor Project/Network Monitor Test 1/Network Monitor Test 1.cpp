// Network Monitor Test 1.cpp : This file contains the 'main' function. Program execution begins and ends there.
#include <iostream>
#include "Fing.h"
#include "Local.h"
#include "Nmap.h"
#include "MacTable.h"

#ifdef _WIN32
#include <windows.h>
#define popen _popen
#define pclose _pclose
#else
#include <unistd.h>
#endif

int main() {
    int Selection;
    while (true) {
        std::cout << "**************************" << std::endl;
        std::cout << "1. Scan Hosts on Subnet" << std::endl;
        std::cout << "2. Run Fing" << std::endl;
        std::cout << "3. Run Nmap" << std::endl;
        std::cout << "4. Parse OUI File" << std::endl;
        std::cout << "5. Check MAC Table" << std::endl;
        std::cout << "6. Exit" << std::endl;

        std::cout << "**************************" << std::endl;
        std::cout << "User: ";
        std::cin >> Selection;

        if (Selection == 6) break;

        switch (Selection) {
        case 1:
            scanIPAddresses();
            break;

        case 2:
#if defined(_WIN32)
            std::cout << "Operating System: Windows" << std::endl;
            runFingWindows();
#elif defined(__linux__)
            std::cout << "Operating System: Linux" << std::endl;
            runFingLinux();
#elif defined(__APPLE__) && defined(__MACH__)
            std::cout << "Operating System: macOS" << std::endl;
            runFingMacOS();
#else
            std::cout << "Operating System: Unknown" << std::endl;
#endif
            break;

        case 3:
#if defined(_WIN32)
            std::cout << "Operating System: Windows" << std::endl;
            runNmapWindows();
#elif defined(__linux__)
            std::cout << "Operating System: Linux" << std::endl;
            runNmapLinux();
#elif defined(__APPLE__) && defined(__MACH__)
            std::cout << "Operating System: macOS" << std::endl;
            runNmapMacOS();
#else
            std::cout << "Operating System: Unknown" << std::endl;
#endif
            break;

        case 4:
            parseOuiStandards();
            break;
        
        case 5:
            checkMacTable();

        default:
            std::cout << "Invalid selection. Please try again." << std::endl;
        }
    }
    return 0;
}