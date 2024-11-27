import time
from scapy.all import sr1
from scapy.layers.l2 import ARP
from database import add_to_database, get_data_from_database

def arp_spoof_detect(packet, info_textbox, root_destroyed):
    if ARP in packet and packet[ARP].op == 2:
        arp_reply_src_mac = packet[ARP].hwsrc
        arp_reply_src_ip = packet[ARP].psrc

        arp_request = ARP(pdst=arp_reply_src_ip)
        arp_response = sr1(arp_request, timeout=2, verbose=0, iface="Wi-Fi")

        if arp_response:
            if arp_response.hwsrc != arp_reply_src_mac:
                spoof_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

                # Check if attack is already logged
                data = get_data_from_database()
                for row in data:
                    if row[0] == spoof_time and row[1] == arp_reply_src_ip and row[2] == arp_response.hwsrc:
                        break
                else:
                    # Log new attack and update UI
                    add_to_database(spoof_time, arp_reply_src_ip, arp_response.hwsrc)
                    if not root_destroyed:
                        update_info_textbox(info_textbox)

                    # Display attack details in the main window
                    info_text = f"\n---------------------------------------------------------\nTarih: {spoof_time} | IP: {arp_reply_src_ip} | Değişen MAC: {arp_response.hwsrc}\n---------------------------------------------------------\n"
                    info_textbox.config(state="normal")
                    info_textbox.insert("end", info_text)
                    info_textbox.config(state="disabled")
                    info_textbox.see("end")

def update_info_textbox(info_textbox):
    info_textbox.config(state="normal")
    info_textbox.delete("1.0", "end")
    info_textbox.config(state="disabled")
