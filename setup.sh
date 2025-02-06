#!/bin/bash

GITHUB_REPO="https://github.com/byfranke/EncryptNotes"
TEMP_DIR="$(mktemp -d)"
INSTALL_DIR="/usr/local/bin"

print_banner() {
echo
echo " _____________________________ "
echo "|                             |"
echo "|   ENCRYPTNOTES INSTALLER    |"
echo "|_____________________________|"
echo
echo "   Secure and Encrypted Notes"
echo "   GitHub: byfranke/EncryptNotes"
echo "---------------------------------"
}

install_dependencies() {
    echo "[*] Checking Python and pip..."
    if ! command -v python3 &> /dev/null; then
        echo "[!] Python3 not found. Installing..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install python3 -y
        elif command -v pacman &> /dev/null; then
            sudo pacman -Syu --noconfirm python
        else
            echo "[!] No package manager found. Install Python3 manually."
            exit 1
        fi
    else
        echo "[+] Python3 found."
    fi

    if ! command -v pip3 &> /dev/null; then
        echo "[!] pip3 not found. Installing..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get install python3-pip -y
        elif command -v pacman &> /dev/null; then
            sudo pacman -S --noconfirm python-pip
        else
            echo "[!] No package manager found. Install pip3 manually."
            exit 1
        fi
    else
        echo "[+] pip3 found."
    fi

    echo "[*] Installing required Python dependencies..."
    pip3 install --upgrade cryptography sqlite3 argparse
    echo "[+] Dependencies installed."
}

install_encryptnotes() {
    echo "[*] Installing EncryptNotes..."
    if [ ! -f "encryptnotes.py" ]; then
        echo "[!] encryptnotes.py not found in current directory."
        return
    fi
    sudo chmod +x encryptnotes.py
    sudo cp encryptnotes.py "$INSTALL_DIR/encryptnotes"
    echo "[+] EncryptNotes installed as /usr/local/bin/encryptnotes"
}

install_encryptnotes_beta() {
    echo "[*] Installing EncryptNotes Beta..."
    if [ ! -f "encryptnotes_beta.py" ]; then
        echo "[!] encryptnotes_beta.py not found in current directory."
        return
    fi
    sudo chmod +x encryptnotes_beta.py
    sudo cp encryptnotes_beta.py "$INSTALL_DIR/encryptnotes_beta"
    echo "[+] EncryptNotes Beta installed as /usr/local/bin/encryptnotes_beta"
}

update_project() {
    echo "[*] Checking for updates from GitHub..."
    git clone "$GITHUB_REPO" "$TEMP_DIR" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "[!] Failed to clone repository. Check your internet connection."
        rm -rf "$TEMP_DIR"
        return
    fi

    BACKUP_DIR="Backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    echo "[*] Moving old files to $BACKUP_DIR..."
    shopt -s extglob
    find . -maxdepth 1 -type f ! -name "$(basename "$0")" ! -name "setup.sh" -exec mv {} "$BACKUP_DIR" \;
    find . -maxdepth 1 -type d ! -name "$BACKUP_DIR" ! -name "." ! -name ".." -exec mv {} "$BACKUP_DIR" \;

    mv "$TEMP_DIR"/* ./
    rm -rf "$TEMP_DIR"
    echo "[+] Updated to the latest version. Backup saved in '$BACKUP_DIR'."
}

show_menu() {
while true; do
    print_banner
    echo "Choose an option:"
    echo
    echo "1) Install EncryptNotes"
    echo "2) Install EncryptNotes Beta"
    echo "3) Check for Updates"
    echo "4) Exit"
    echo
    read -p "Enter your choice: " choice
    case $choice in
        1) install_encryptnotes ;;
        2) install_encryptnotes_beta ;;
        3) update_project ;;
        4) echo "Exiting..."; exit 0 ;;
        *) echo "[!] Invalid option. Try again." ;;
    esac
    echo
    read -p "Press Enter to return to the menu..." dummy
done
}

show_menu
