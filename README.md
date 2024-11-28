# ARP Spoof Detection

A Python-based application to detect ARP spoofing attacks in real-time, featuring a user-friendly GUI and SQLite database logging for tracking attack history.

## Features  
- **Real-Time Detection:** Monitors network traffic to identify ARP spoofing.  
- **Attack History Logging:** Saves detected attacks in a database for later review.  
- **Intuitive GUI:** Simplifies monitoring and log access with a Tkinter-based interface.  

## Requirements  
- **Windows Users:** You must install **Npcap** for packet capturing. Download it from [Npcap official site](https://nmap.org/npcap/).   
- **Dependencies:**  
  - `tkinter`: For GUI  
  - `scapy`: For network packet analysis  
  - `sqlite3`: For database management  

Install required libraries using:  
```bash
pip install scapy
```

## File Overview  
- **`main.py`**: Entry point for launching the application and GUI.  
- **`gui.py`**: Defines the Tkinter-based graphical interface for monitoring and interaction.  
- **`arp_detection.py`**: Implements ARP spoof detection logic.  
  - **Note:** Ensure the `iface` parameter in `arp_detection.py` matches your network interface (e.g., `"Wi-Fi"`).  
- **`database.py`**: Handles SQLite database creation and attack log storage.  

## Installation and Usage  

### Clone the Repository:  
```bash
git clone https://github.com/MiracKayikci/Arp-Spoof-Detector-Python-Tkinter.git
```
### How to Use:  
- **Start Monitoring:** Click **"Start Monitoring"** to initiate ARP spoof detection.  
- **View Attack History:** Use the **"View Attack History"** button to see previously detected attacks.  
- **Exit Safely:** Close the app using the **"Exit"** button.  


