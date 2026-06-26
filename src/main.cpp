#include <iostream>
#include <csignal>
#include <filesystem> // Required for automatic directory management
#include <ctime>       // Required for generating unique session timestamps
#include "packet_handler.h"
#include "metrics.h"

using namespace std;
namespace fs = std::filesystem;

void signal_handler(int signum) {
    cout << "\n[!] Stopping packet capture gracefully..." << endl;
    if (global_handle != nullptr) {
        pcap_breakloop(global_handle); 
    }
}

int main() {
    signal(SIGINT, signal_handler);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error finding network devices: " << errbuf << endl;
        return 1;
    }

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
    
    // Prompt for session logging
    char save_choice;
    pcap_dumper_t* dumper = nullptr;
    string target_path = "";
    
    cout << "\nDo you want to log this capture session to a unique .pcap file? (y/n): ";
    cin >> save_choice;

    pcap_t* handle = pcap_open_live(choice->name, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        cerr << "Failed to open adapter: " << errbuf << endl;
        pcap_freealldevs(alldevs);
        return -1;
    }

    if (save_choice == 'y' || save_choice == 'Y') {
        // 1. Ensure the target directory exists
        fs::create_directory("captures");

        // 2. Sample current system time
        time_t rawtime;
        time(&rawtime);
        struct tm* timeinfo = localtime(&rawtime);

        // 3. Format the timestamp into a distinct filename string
        char filename_buf[100];
        strftime(filename_buf, sizeof(filename_buf), "captures/capture_%Y%m%d_%H%M%S.pcap", timeinfo);
        target_path = string(filename_buf);

        // 4. Open unique file dumper handle
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

    // Pass the active dynamic dumper pointer to the packet handler pipeline
    pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(dumper));

    print_metrics_dashboard();

    // Close and finalize the capture file safely
    if (dumper != nullptr) {
        pcap_dump_close(dumper);
        cout << "[+] Packet trace log finalized and saved safely to: " << target_path << endl;
    }

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}