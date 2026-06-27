#include <iostream>
#include <csignal>
#include <filesystem> // Required for automatic directory management
#include <ctime>       // Required for generating unique session timestamps
#include "packet_handler.h"
#include "metrics.h"
#include <cstdint>
using namespace std;
namespace fs = std::filesystem;

// Intercepts termination events to unwind the processing loop
void signal_handler(int signum) {
    cout << "\n[!] Stopping packet capture..." << endl;
    if (global_handle != nullptr) {
        pcap_breakloop(global_handle); 
    }
}

int main() {
    // Register custom interrupt vector callback to cleanly break loop architectures
    signal(SIGINT, signal_handler);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;

    // Enumerate hardware and virtual adapter configurations from the system kernel
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error finding network devices: " << errbuf << endl;
        return 1;
    }

    // Print active network device directory
    int i = 0;
    for (pcap_if_t* d = alldevs; d != NULL; d = d->next) {
        cout << ++i << ". " << d->name << (d->description ? " (" + string(d->description) + ")" : "") << endl;
    }

    if (i == 0) {
        cout << "No interfaces found. Check Npcap installations." << endl;
        pcap_freealldevs(alldevs);
        return 0;
    }

    int choice_num;
    cout << "\nEnter the interface number to analyze (1-" << i << "): ";
    cin >> choice_num;

    if (choice_num < 1 || choice_num > i) {
        cout << "Invalid choice selection. Exiting." << endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    pcap_if_t* choice = alldevs;
    for (int c = 1; c < choice_num; c++) {
        choice = choice->next;
    }

    // Configure selection criteria for runtime filtering rules
    cout << "\nChoose a Protocol Filter Option:\n";
    cout << "1. Show All Captured Traffic\n";
    cout << "2. TCP Only\n";
    cout << "3. UDP Only\n";
    cout << "4. ICMP Only\n";
    cout << "Enter filter selection (1-4): ";
    cin >> protocol_filter;

    if (protocol_filter < 1 || protocol_filter > 4) {
        cout << "Invalid selection. Defaulting to Show All Traffic.\n";
        protocol_filter = 1;
    }
    
    // Prompt user to enable disk-logging capabilities
    char save_choice;
    pcap_dumper_t* dumper = nullptr;
    string target_path = "";
    
    cout << "\nDo you want to log this capture session to a unique .pcap file? (y/n): ";
    cin >> save_choice;

    // Instantiate raw link layer capture descriptor 
    pcap_t* handle = pcap_open_live(choice->name, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        cerr << "Failed to open adapter: " << errbuf << endl;
        pcap_freealldevs(alldevs);
        return -1;
    }

    // Initialize uniquely timestamped filename path if disk persistence is requested
    if (save_choice == 'y' || save_choice == 'Y') {
        // Automatically creates the target folder at root if missing
        fs::create_directory("captures");

        // Format system context clock to make unique session logs
        time_t rawtime;
        time(&rawtime);
        struct tm* timeinfo = localtime(&rawtime);

        char filename_buf[100];
        strftime(filename_buf, sizeof(filename_buf), "captures/capture_%Y%m%d_%H%M%S.pcap", timeinfo);
        target_path = string(filename_buf);

        // Instantiate binary dump file writer stream object
        dumper = pcap_dump_open(handle, target_path.c_str());
        if (dumper == nullptr) {
            cerr << "Warning: Could not create dump file. Continuing without saving." << endl;
        } else {
            cout << "[+] Session file logging active. Saving to '" << target_path << "'..." << endl;
        }
    }

    global_handle = handle; 

    cout << "\nAnalyzing live traffic on: " << (choice->description ? choice->description : choice->name) << "..." << endl;
    cout << "Press [Ctrl + C] at any time to stop session and view summary dashboard.\n" << endl;

    // Execute streaming evaluation loop, passing the dynamic dumper context down
    pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(dumper));

    // Display runtime session aggregate analytics dashboard
    print_metrics_dashboard();

    // Close and finalize the capture file descriptor safely
    if (dumper != nullptr) {
        pcap_dump_close(dumper);
        cout << "[+] Packet trace log finalized and saved safely to: " << target_path << endl;
    }

    // Release active adapter binding locks and drop device structures cleanly
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}