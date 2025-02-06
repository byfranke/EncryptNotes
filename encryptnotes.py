#!/usr/bin/env python3

import sqlite3
import datetime
from cryptography.fernet import Fernet
import hashlib
import os
import glob
import getpass
import argparse
import itertools

user_home = os.path.expanduser("~")
database_dir = os.path.join(user_home, 'Documents', 'Database')
database_path = os.path.join(database_dir, 'encryptnotes.db')

if not os.path.exists(database_dir):
    os.makedirs(database_dir)

conn = sqlite3.connect(database_path)


def create_table():
    conn.execute('''
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            encrypted_note TEXT NOT NULL,
            encryption_key TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    conn.commit()


def generate_key():
    return Fernet.generate_key()


def encrypt_note(note, encryption_key):
    cipher_suite = Fernet(encryption_key)
    return cipher_suite.encrypt(note.encode())


def decrypt_note(encrypted_note, encryption_key):
    cipher_suite = Fernet(encryption_key)
    return cipher_suite.decrypt(encrypted_note).decode()


def add_note(note):
    while True:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        encryption_key = generate_key()
        password = getpass.getpass("\nEnter the password to encrypt the note: ")
        confirm_password = getpass.getpass("Confirm the password: ")

        if password == confirm_password:
            encrypted_note = encrypt_note(note, encryption_key)
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            conn.execute('INSERT INTO notes (timestamp, encrypted_note, encryption_key, password_hash) VALUES (?, ?, ?, ?)',
                         (timestamp, encrypted_note, encryption_key, password_hash))
            conn.commit()
            print("Note added successfully!")
            return True
        else:
            print("Passwords do not match. Please try again.\n")

def edit_note(note_id, encrypted_current_note, current_encryption_key):
    current_note = decrypt_note(encrypted_current_note, current_encryption_key)

    new_content = input("Enter the new content for the note: ")
    print("\nOptions:")
    print("1 - Add this content to the existing note")
    print("2 - Replace the existing note with this content")
    choice = input("Choose an option: ")

    if choice == '1':
        updated_note = current_note + "\n" + new_content
    elif choice == '2':
        updated_note = new_content
    else:
        print("Invalid option. No changes were made.")
        return

    password = getpass.getpass("\nEnter the new password to encrypt the note (or press enter to keep the old one): ")

    if not password:
        encryption_key = current_encryption_key
        cursor = conn.execute('SELECT password_hash FROM notes WHERE id = ?', (note_id,))
        password_hash = cursor.fetchone()[0]
    else:
        encryption_key = generate_key()
        confirm_password = getpass.getpass("Confirm the new password: ")
        if password != confirm_password:
            print("Passwords do not match. The note was not updated.")
            return
        password_hash = hashlib.sha256(password.encode()).hexdigest()

    encrypted_updated_note = encrypt_note(updated_note, encryption_key)

    conn.execute('UPDATE notes SET encrypted_note = ?, encryption_key = ?, password_hash = ? WHERE id = ?',
                 (encrypted_updated_note, encryption_key, password_hash, note_id))
    conn.commit()
    print("Note updated successfully!")


def delete_note(note_id):
    conn.execute('DELETE FROM notes WHERE id = ?', (note_id,))
    conn.commit()
    print(f"Note {note_id} deleted successfully!")

def get_note_content_by_id(note_id):
    cursor = conn.execute('SELECT encrypted_note, encryption_key, password_hash FROM notes WHERE id = ?', (note_id,))
    fetch_result = cursor.fetchone()

    if fetch_result is None:
        print(f"No note found with ID {note_id}.")
        return None, None, None

    return fetch_result

def search_note(note_id, *search_terms):
    cursor = conn.execute('SELECT encrypted_note, encryption_key, password_hash FROM notes WHERE id = ?', (note_id,))
    result = cursor.fetchone()

    if result:
        encrypted_note, encryption_key, stored_password_hash = result

        password = getpass.getpass(f"Enter the password to decrypt note {note_id}: ")
        input_password_hash = hashlib.sha256(password.encode()).hexdigest()

        if input_password_hash == stored_password_hash:
            try:
                decrypted_note = decrypt_note(encrypted_note, encryption_key)
                
                patterns_to_search = [
                    "".join(search_terms),
                    "".join(reversed(search_terms)),
                    ".".join(search_terms),
                    ".".join(reversed(search_terms))
                ]
                
                matched_lines = []
                for pattern in patterns_to_search:
                    if pattern in decrypted_note:
                        for line in decrypted_note.split("\n"):
                            if pattern in line:
                                matched_lines.append(line)

                if matched_lines:
                    print(f"\nNote {note_id} contains the terms:\n")
                    for line in matched_lines:
                        print(line)
                else:
                    print(f"\nNote {note_id} does not contain any of the searched terms.")

            except Exception as e:
                print("Decryption error or another error occurred: ", str(e))
        else:
            print("Incorrect password.")
    else:
        print(f"No note found with ID {note_id}.")

def export_to_txt(note_content, path):
    try:
        if os.path.isdir(path):
            filename = "note_exported_" + datetime.datetime.now().strftime('%Y%m%d_%H%M%S') + ".txt"
            path = os.path.join(path, filename)

        with open(path, 'w') as file:
            file.write(note_content)
        print(f"Note exported to {path} successfully!")
    except Exception as e:
        print(f"An error occurred with your option: {str(e)}")


def list_notes():
    cursor = conn.execute('SELECT id, timestamp FROM notes')
    for row in cursor:
        print(f"{row[0]} - {row[1]}")

    note_id_input = input("Enter the note ID you want to read (or 0 to exit): ")

    if not note_id_input.isdigit():
        print("Invalid input. Please enter a valid note ID.")
        return

    note_id = int(note_id_input)

    if note_id != 0:
        cursor = conn.execute('SELECT encrypted_note, encryption_key, password_hash FROM notes WHERE id = ?', (note_id,))
        fetch_result = cursor.fetchone()

        if fetch_result is None:
            print(f"No note found with ID {note_id}.")
            return

        password = getpass.getpass("Enter the password to decrypt the note: ")
        encrypted_note, encryption_key, stored_password_hash = fetch_result
        input_password_hash = hashlib.sha256(password.encode()).hexdigest()

        if input_password_hash == stored_password_hash:
            try:
                decrypted_note = decrypt_note(encrypted_note, encryption_key)
                print(f"\nNote {note_id}:\n{decrypted_note}")
            except:
                print("Decryption error.")
                return
            
            print("\nOptions:")
            print("1 - Edit")
            print("2 - Delete")
            print("3 - Export to TXT")
            print("4 - Go back to main menu")
            option = input("Choose an option: ")

            try:
                if option == '1':
                    edit_note(note_id, encrypted_note, encryption_key)
                elif option == '2':
                    delete_note(note_id)
                    return
                elif option == '3':
                    path = input("Enter the path for the exported TXT file or press enter to use the current directory: ")
                    if not path:
                        path = os.path.join(os.getcwd(), f"note_{note_id}.txt")
                    export_to_txt(decrypted_note, path)
                elif option == '4':
                    return
                else:
                    print("Invalid option. Returning to main menu.")
            except Exception as e:
                print(f"An error occurred with your option: {e}")
        else:
            print("Incorrect password.")

import os

def import_txt_file(pattern):
    if os.path.isdir(pattern):
        pattern = os.path.join(pattern, "*.txt")

    file_paths = glob.glob(pattern)
    if not file_paths:
        print(f"No files found matching '{pattern}'")
        return

    contents = []
    for file_path in sorted(file_paths):  
        encodings = ['utf-8', 'latin-1', 'ISO-8859-1', 'windows-1252']
        note_content = None
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as file:
                    note_content = file.read()
                contents.append(note_content)  
                break
            except UnicodeDecodeError:
                pass

    all_content = "\n\n".join(contents)  

    if not all_content.strip():
        print(f"Failed to decode files matching '{pattern}' using the tried encodings.")
        return

    if add_note(all_content):
        print(f"Files matching '{pattern}' imported and encrypted successfully!")

def main():
    create_table()

    parser = argparse.ArgumentParser(description='Notes encryption script.')
    parser.add_argument('-n', '--new-note', action='store_true', help='Enter note creation mode.')
    parser.add_argument('-i', '--import', type=str, dest="import_file", help='Path to import a TXT file or multiple TXT files into notes.')
    parser.add_argument('-s', '--search', nargs='+', help='Search within a specific note. Usage: -s <note_id> <keyword1> <keyword2> ...')

    args = parser.parse_args()

    if args.new_note:
        note = input("Enter your note: ")
        add_note(note)
        return

    if args.import_file:
        import_txt_file(args.import_file)
        return

    if args.search:
        try:
            note_id = int(args.search[0])
            search_terms = args.search[1:]
            search_note(note_id, *search_terms)
        except ValueError:
            print("Invalid note ID. Please provide a valid integer.")
        return

    while True:
        print("""



  ____|                                   |     \  |         |               
  __|    __ \    __|   __|  |   |  __ \   __|    \ |   _ \   __|   _ \   __| 
  |      |   |  (     |     |   |  |   |  |    |\  |  (   |  |     __/ \__ \ 
 _____| _|  _| \___| _|    \__, |  .__/  \__| _| \_| \___/  \__| \___| ____/ 
                           ____/  _|                                         

                         github.com/byfranke v0.2                                                                                                  
        """)
        print("Options:")
        print("1 - New note")
        print("2 - Import TXT file")
        print("3 - List notes")  
        print("4 - Exit")
        option = input("Choose an option: ")

        if option == '1':
            note = input("Enter your note: ")  
            if add_note(note):
                break
        elif option == '2':
            file_path = input("Enter the path to the TXT file you want to import: ")
            import_txt_file(file_path)
        elif option == '3':
            list_notes()  
        elif option == '4':
            break
        else:
            print("Invalid option. Choose again.")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram closed.")
        conn.close()
        exit()
