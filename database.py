import sqlite3

def create_database():
    conn = sqlite3.connect('arp_spoof_db.db')
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS arp_spoof_log (
        timestamp text,
        ip text,
        spoofed_mac text
    )''')

    conn.commit()
    conn.close()

def add_to_database(timestamp, ip, spoofed_mac):
    conn = sqlite3.connect('arp_spoof_db.db')
    c = conn.cursor()

    c.execute('INSERT INTO arp_spoof_log (timestamp, ip, spoofed_mac) VALUES (?, ?, ?)', (timestamp, ip, spoofed_mac))

    conn.commit()
    conn.close()

def get_data_from_database():
    conn = sqlite3.connect('arp_spoof_db.db')
    c = conn.cursor()

    c.execute('SELECT * FROM arp_spoof_log')
    data = c.fetchall()

    conn.close()
    return data
