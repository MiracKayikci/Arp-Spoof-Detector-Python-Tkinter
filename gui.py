import threading
import time
import tkinter as tk
from tkinter import messagebox
from scapy.all import sniff
from arp_detection import arp_spoof_detect
from database import create_database, get_data_from_database

def update_info_textbox():
    info_textbox.config(state=tk.NORMAL)
    info_textbox.delete("1.0", tk.END)
    info_textbox.config(state=tk.DISABLED)

def gecmis_saldarilari_goster():
    # Yeni bir pencere oluştur
    gecmis_saldarilar_penceresi = tk.Toplevel()
    gecmis_saldarilar_penceresi.title("Geçmiş Saldırılar")
    gecmis_saldarilar_penceresi.geometry("600x400")

    # Metin kutusu ve kaydırma çubuğu için bir çerçeve oluştur
    frame = tk.Frame(gecmis_saldarilar_penceresi)
    frame.pack(fill=tk.BOTH, expand=True)

    # Kaydırma çubuğu oluştur
    scrollbar = tk.Scrollbar(frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # Geçmiş saldırıları bir metin kutusunda göster
    gecmis_saldarilar_metin = tk.Text(frame, wrap=tk.WORD, font=("Arial", 12), fg="black", height=20, width=70,
                                      yscrollcommand=scrollbar.set)
    gecmis_saldarilar_metin.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # Kaydırma çubuğunu metin kutusuna bağla
    scrollbar.config(command=gecmis_saldarilar_metin.yview)

    # Veritabanından verileri al
    veriler = get_data_from_database()

    # Metin kutusuna verileri ekle
    for satir in veriler:
        gecmis_saldarilar_metin.insert(tk.END, f"Tarih: {satir[0]} | IP: {satir[1]} | Değişen MAC: {satir[2]}\n\n")

root_destroyed = False

def ekran_cikis():
    global root_destroyed
    root_destroyed = True
    root.destroy()

def start_detection():
    status_label.config(text="ARP Spoof Detection Started", fg="green", font=("Times New Roman", 12, "bold"))

    while True:
        sniff(filter="arp", prn=arp_spoof_detect, store=0)
        time.sleep(5)

def start_detection_thread():
    detection_thread = threading.Thread(target=start_detection)
    detection_thread.daemon = True
    detection_thread.start()

# Tkinter arayüzü
root = tk.Tk()
root.title("ARP Spoof Detection")
root.geometry("600x550+600+140")

def disable_event():
    messagebox.showinfo("Bilgi", "Ekranı kapatmak için 'ÇIKIŞ' butonunu kullanın")
# Pencerenin kapatma düğmesini devre dışı bırakma
root.protocol("WM_DELETE_WINDOW", disable_event)

frame = tk.Frame(root)
frame.pack()

start_button = tk.Button(frame, text="İZLEMEYİ BAŞLAT", bg="green", fg="white", font=("Arial", 10, "bold"),command=start_detection_thread)
start_button.pack(side=tk.LEFT, padx=10)

exit_button = tk.Button(frame, text="ÇIKIŞ", bg="red", fg="white", font=("Arial", 10, "bold"), command=ekran_cikis)
exit_button.pack(side=tk.RIGHT, padx=10)

status_label = tk.Label(root, text="")
status_label.pack()

# Bilgiyi göstermek için metin kutusu
info_textbox = tk.Text(root, wrap=tk.WORD, font=("Times New Roman", 12, "bold"), fg="red", height=15, width=70)
info_textbox.pack(fill=tk.BOTH, expand=True)

gecmis_saldarilar_butonu = tk.Button(root, text="Geçmiş Saldırılar", bg="lightblue", fg="black", font=("Arial", 10, "bold"), command=gecmis_saldarilari_goster)
gecmis_saldarilar_butonu.pack(pady=10)

create_database()
root.mainloop()


def create_gui():
    return None