# Encryption and Note Management Script

![image](https://github.com/byfranke/encryptnotes/assets/131370932/c90262b4-2296-4e23-9723-82a6a5f0cce2)

# Description:
This Python script provides functionalities for encrypting, managing, and interacting with text notes securely. It includes features such as adding new notes, editing, deleting, exporting to TXT files, and importing from TXT files.


# Key Features:

• Secure Encryption: Utilizes the cryptography library to encrypt notes, safeguarding them with dynamic keys and passwords.

• SQLite Database: Organizes notes systematically within an SQLite database for easy management.

• Command-Line Interface (CLI): Offers a simple interface for interaction, allowing actions such as adding, editing, deleting, importing, and exporting notes.

• Search and Filtering: Employs advanced search capabilities, enabling keyword searches within encrypted notes.

• TXT Import and Export: Facilitates the import of content from TXT files to create new notes and exports notes to TXT files.


# Usage Instructions:

Run the script from the command line.
Choose between adding a new note, importing from a TXT file, listing existing notes, or exiting.
For existing notes, options include editing, deleting, and exporting.

options:
  -h, --help            show this help message and exit
  -n, --new-note        Enter note creation mode.
  -i IMPORT_FILE, --import IMPORT_FILE
                        Path to import a TXT file or multiple TXT files into notes.
  -s SEARCH [SEARCH ...], --search SEARCH [SEARCH ...]
                        Search within a specific note. Usage: -s <note_id> <keyword1> <keyword2> ...


# Notes:

Ensure secure passwords are provided when adding or editing notes, as these passwords are used in encryption.
The code utilizes popular libraries such as sqlite3, cryptography, and argparse.

# Installation For Linux

Step : 1 Download

```
git clone https://github.com/byfranke/encryptnotes
```
Step : 2 Move to directory
```
cd encryptnotes
```
Step : 3 For installing tools in directory
```
bash setup.sh
```
Step : 4 Run
```
encryptnotes
```

# Donations

If you find these tools useful and would like to support ongoing development and maintenance, please consider making a donation. Your contribution helps ensure that these tools are regularly updated and improved, benefiting the cybersecurity community. Any amount is greatly appreciated and will make a significant difference in supporting this project. Thank you for considering supporting this work!

Address Bitcoin: bc1qkdh3eqpj87q5hlhc7pvm025hmsd9zp2kadxf76
