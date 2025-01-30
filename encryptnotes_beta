#!/usr/bin/env python3

import os
import sys
import glob
import base64
import shutil
import getpass
import argparse
import sqlite3
import hashlib
import logging
import datetime
import pyotp
from rich.console import Console
from rich.table import Table
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import tkinter as tk
from tkinter import messagebox

# Configurações iniciais
logging.basicConfig(filename='encryptnotes.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
console = Console()

# Caminhos
home = os.path.expanduser("~")
db_dir = os.path.join(home, 'Documents', 'Database')
db_path = os.path.join(db_dir, 'encryptnotes.db')
if not os.path.exists(db_dir):
    os.makedirs(db_dir)

# Conexão com o banco de dados
conn = sqlite3.connect(db_path)
conn.execute('PRAGMA foreign_keys = ON')

# Tabelas
conn.execute('''
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    salt BLOB NOT NULL,
    encrypted_note BLOB NOT NULL,
    hashed_pass BLOB NOT NULL,
    attempts INTEGER DEFAULT 0
)
''')
conn.execute('''
CREATE TABLE IF NOT EXISTS tags (
    id INTEGER PRIMARY KEY,
    note_id INTEGER NOT NULL,
    tag TEXT NOT NULL,
    FOREIGN KEY(note_id) REFERENCES notes(id) ON DELETE CASCADE
)
''')
conn.execute('''
CREATE TABLE IF NOT EXISTS user2fa (
    id INTEGER PRIMARY KEY,
    secret TEXT NOT NULL
)
''')
conn.commit()

# Funções de segurança
def derive_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    return kdf.derive(password.encode())

def encrypt_data(data, key):
    return Fernet(base64.urlsafe_b64encode(key)).encrypt(data.encode())

def decrypt_data(data, key):
    return Fernet(base64.urlsafe_b64encode(key)).decrypt(data).decode()

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

# 2FA
def setup_2fa():
    secret = pyotp.random_base32()
    conn.execute('INSERT INTO user2fa (secret) VALUES (?)', (secret,))
    conn.commit()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name='EncryptNotes', issuer_name='SecureApp')
    console.print(f"[bold green]Scan this QR code URI in your 2FA app:\n{uri}[/bold green]")

def verify_2fa():
    secret = conn.execute('SELECT secret FROM user2fa').fetchone()
    if not secret:
        return True  # 2FA não configurado
    code = getpass.getpass("Enter 2FA code: ")
    return pyotp.TOTP(secret[0]).verify(code)

# Backup
def backup_database():
    backup_path = os.path.join(db_dir, f'backup_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.db')
    try:
        shutil.copy2(db_path, backup_path)
        console.print(f"[bold green]Backup created at {backup_path}[/bold green]")
        logging.info(f"Backup created at {backup_path}")
    except Exception as e:
        console.print(f"[bold red]Backup failed: {e}[/bold red]")
        logging.error(f"Backup failed: {e}")

# Interface gráfica básica
def show_note_gui(note_id, content):
    root = tk.Tk()
    root.title(f"Note {note_id}")
    text = tk.Text(root)
    text.insert(tk.END, content)
    text.pack()
    root.mainloop()

# Funções principais
def add_note():
    if not verify_2fa():
        console.print("[bold red]2FA failed[/bold red]")
        return
    note = input("\nEnter note: ")
    pwd = getpass.getpass("Password: ")
    cfm = getpass.getpass("Confirm: ")
    if pwd != cfm:
        console.print("[bold red]Passwords do not match[/bold red]")
        return
    salt = os.urandom(16)
    key = derive_key(pwd, salt)
    enc = encrypt_data(note, key)
    hsh = hashlib.sha256(pwd.encode()).digest()
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn.execute('INSERT INTO notes (timestamp, salt, encrypted_note, hashed_pass) VALUES (?,?,?,?)', (timestamp, salt, enc, hsh))
    note_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
    tags = input("Tags (comma separated): ").split(',')
    for tag in tags:
        tag = tag.strip()
        if tag:
            conn.execute('INSERT INTO tags (note_id, tag) VALUES (?,?)', (note_id, tag))
    conn.commit()
    console.print("[bold green]Note added[/bold green]")
    logging.info(f"Note {note_id} added")

def list_notes():
    cur = conn.execute('SELECT id, timestamp FROM notes')
    table = Table(title="Notes")
    table.add_column("ID")
    table.add_column("Timestamp")
    for row in cur:
        table.add_row(str(row[0]), row[1])
    console.print(table)
    note_id = input("Enter ID to view (0=back): ")
    if not note_id.isdigit() or note_id == '0':
        return
    if not verify_2fa():
        console.print("[bold red]2FA failed[/bold red]")
        return
    row = conn.execute('SELECT salt, encrypted_note, hashed_pass FROM notes WHERE id=?', (note_id,)).fetchone()
    if not row:
        console.print("[bold red]Not found[/bold red]")
        return
    pwd = getpass.getpass("Password: ")
    if hashlib.sha256(pwd.encode()).digest() != row[2]:
        console.print("[bold red]Wrong password[/bold red]")
        return
    try:
        decrypted = decrypt_data(row[1], derive_key(pwd, row[0]))
        console.print(f"[bold cyan]\nNote {note_id}[/bold cyan]\n{decrypted}\n")
        console.print("1=Edit 2=Delete 3=Export 4=Back")
        choice = input("> ")
        if choice == '1':
            edit_note(note_id, pwd, row[0], row[1], row[2])
        elif choice == '2':
            delete_note(note_id)
        elif choice == '3':
            export_note(note_id, decrypted)
        else:
            return
    except Exception as e:
        console.print(f"[bold red]Decryption error: {e}[/bold red]")
        logging.error(f"Decryption error for note {note_id}: {e}")

def edit_note(note_id, old_pwd, salt, enc, hsh):
    current_note = decrypt_data(enc, derive_key(old_pwd, salt))
    new_content = input("New content: ")
    console.print("1=Append 2=Replace")
    choice = input("> ")
    if choice == '1':
        updated = current_note + "\n" + new_content
    elif choice == '2':
        updated = new_content
    else:
        return
    new_pwd = getpass.getpass("New password (empty=keep same): ")
    if not new_pwd:
        key = derive_key(old_pwd, salt)
        new_hash = hsh
        new_salt = salt
    else:
        cfm = getpass.getpass("Confirm new: ")
        if new_pwd != cfm:
            console.print("[bold red]Mismatch[/bold red]")
            return
        new_salt = os.urandom(16)
        key = derive_key(new_pwd, new_salt)
        new_hash = hashlib.sha256(new_pwd.encode()).digest()
    new_enc = encrypt_data(updated, key)
    conn.execute('UPDATE notes SET salt=?, encrypted_note=?, hashed_pass=? WHERE id=?', (new_salt, new_enc, new_hash, note_id))
    conn.commit()
    console.print("[bold green]Updated[/bold green]")
    logging.info(f"Note {note_id} updated")

def delete_note(note_id):
    if not verify_2fa():
        console.print("[bold red]2FA failed[/bold red]")
        return
    conn.execute('DELETE FROM notes WHERE id=?', (note_id,))
    conn.commit()
    console.print(f"[bold green]Note {note_id} deleted[/bold green]")
    logging.info(f"Note {note_id} deleted")

def export_note(note_id, content):
    path = input("Path (empty=current dir): ")
    if not path:
        path = f"note_{note_id}.txt"
    try:
        with open(path, 'w') as f:
            f.write(content)
        console.print(f"[bold green]Exported to {path}[/bold green]")
        logging.info(f"Note {note_id} exported to {path}")
    except Exception as e:
        console.print(f"[bold red]{e}[/bold red]")
        logging.error(f"Export failed for note {note_id}: {e}")

# Função principal
def main():
    parser = argparse.ArgumentParser(description='EncryptNotes - Secure Note Manager')
    parser.add_argument('--setup-2fa', action='store_true', help='Set up 2FA')
    parser.add_argument('--backup', action='store_true', help='Create a backup')
    args = parser.parse_args()

    if args.setup_2fa:
        setup_2fa()
        return
    if args.backup:
        backup_database()
        return

    while True:
        console.print("""
[bold cyan]

  ____|                                   |     \  |         |               
  __|    __ \    __|   __|  |   |  __ \   __|    \ |   _ \   __|   _ \   __| 
  |      |   |  (     |     |   |  |   |  |    |\  |  (   |  |     __/ \__ \ 
 _____| _|  _| \___| _|    \__, |  .__/  \__| _| \_| \___/  \__| \___| ____/ 
                           ____/  _|                                         

                         github.com/byfranke Beta              


1 - New note
2 - List notes
3 - Setup 2FA
4 - Backup
5 - Exit
[/bold cyan]
""")
        choice = input("> ")
        if choice == '1':
            add_note()
        elif choice == '2':
            list_notes()
        elif choice == '3':
            setup_2fa()
        elif choice == '4':
            backup_database()
        elif choice == '5':
            break
        else:
            console.print("[bold red]Invalid option[/bold red]")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Interrupted[/bold red]")
    finally:
        conn.close()
