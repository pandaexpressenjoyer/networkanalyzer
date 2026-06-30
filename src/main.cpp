#include <iostream>
#include <csignal>
#include <filesystem>
#include <ctime>
#include <thread>      
#include "packet_handler.h"
#include "metrics.h"

using namespace std;
namespace fs = std::filesystem;

void signal_handler(int signum) {
    // 1. Tell the UI loop to stop refreshing
    is_capturing = false; 
    
    // 2. Tell the Npcap background loop to safely break
    if (global_handle != nullptr) {
        pcap_breakloop(global_handle); 
    }
}

int main() {
    signal(SIGINT, signal_handler);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) return 1;

    int i = 0;
    for (pcap_if_t* d = alldevs; d != NULL; d = d->next) {
        cout << ++i << ". " << d->name << (d->description ? " (" + string(d->description) + ")" : "") << endl;
    }

    if (i == 0) return 0;

    int choice_num;
    cout << "\nEnter the interface number to analyze: ";
    cin >> choice_num;

    pcap_if_t* choice = alldevs;
    for (int c = 1; c < choice_num; c++) choice = choice->next;

    cout << "Choose a Protocol Filter Option (1-4): ";
    cin >> protocol_filter;

    char save_choice;
    pcap_dumper_t* dumper = nullptr;
    string target_path = "";
    cout << "Log capture to a .pcap file? (y/n): ";
    cin >> save_choice;

    pcap_t* handle = pcap_open_live(choice->name, 65536, 1, 1000, errbuf);
    if (handle == NULL) return -1;

    if (save_choice == 'y' || save_choice == 'Y') {
        fs::create_directory("captures");
        time_t rawtime; time(&rawtime); struct tm* timeinfo = localtime(&rawtime);
        char filename_buf[100];
        strftime(filename_buf, sizeof(filename_buf), "captures/capture_%Y%m%d_%H%M%S.pcap", timeinfo);
        target_path = string(filename_buf);
        dumper = pcap_dump_open(handle, target_path.c_str());
    }

    global_handle = handle; 

   
    // Spawn a background thread to handle all packet capturing and saving
    std::thread capture_thread(pcap_loop, handle, 0, packet_handler, reinterpret_cast<u_char*>(dumper));

    // While the background thread works, use our Main Thread to draw the live UI
    draw_live_dashboard();

    // When Ctrl+C is pressed, wait for the capture thread to safely shut down
    system("cls");
    cout << "[!] Shutting down threads and saving files safely..." << endl;
    if (capture_thread.joinable()) {
        capture_thread.join();
    }

    if (dumper != nullptr) {
        pcap_dump_close(dumper);
        cout << "[+] Packet trace log finalized and saved safely to: " << target_path << endl;
    }

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}