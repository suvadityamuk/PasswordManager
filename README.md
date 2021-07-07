# PasswordManager

## Working and implementations
This program, although written in one single file, has been made flexible using the development in the form of functions.  
Following packages were used :
- `termcolor`
- `pyfiglet`
- `sqlite3`
- `sys`
- `os`
- `re`
- `cryptography`
- `prettytable`
- `colorama`  


The program maintains one Main table which holds the login data of the user. All passwords are hashed into SHA-512 and during log-in, the hashes are compared.  
On authentication, the user gets the array of functions needed. Each user has a single table, which contains their passwords in AES-256 encrypted format, along with their keys and nonces.  
On querying the table, each of those pieces are retrieved independently and used to decrypt the password to present to the user in the form of a table.
An implementation of a Password Manager using SQLite and Cryptography (SHA-512 and AES-256)

## How to run

Simply download the file and make sure you have the required imports. Once checked, run the python file. Alternatively, use Google Colab or AWS Cloud9 or any such online services for the same.
