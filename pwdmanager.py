# !pip install pyfiglet
# !pip install termcolor
# !pip install getpass4
# !pip install cryptography
# !pip install prettytable
# !pip install colorama
# !pip install sqlite3
from termcolor import cprint
from pyfiglet import figlet_format
import sqlite3
import sys
import re
import os
#from getpass4 import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from prettytable import PrettyTable
from colorama import init
init(strip=not sys.stdout.isatty())

dbcon = sqlite3.connect('Pwds.db')
dbcursor = dbcon.cursor()


def ClearTerminalScreen():
    os.system("cls")


def EncryptPassword(pwd, username):  # returns enc.data, key, nonce
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    return aesgcm.encrypt(nonce=nonce, data=bytes(pwd, encoding='utf-8'), associated_data=bytes(username, encoding='utf-8')), key, nonce


def DecryptPassword(key, nonce, data, as_data):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce=nonce, data=data, associated_data=as_data)


def HashPassword(key):
    dig = hashes.Hash(hashes.SHA512())
    dig.update(bytes(key, encoding='utf-8'))
    return dig.finalize()


def CompareHash(tablehash, userenteredkey):
    a = HashPassword(userenteredkey)
    return 1 if a == tablehash else 0


def ConfirmCredentials():
    print('Enter your username and password to continue\n')
    username = str(input('Username: '))
    # password = str(getpass(prompt='Password: ', char = '*'))
    password = str(input('Password: '))
    dbcursor.execute(
        f'''SELECT * FROM MainHashManager WHERE username = '{username}' ''')
    hash_from_table_list = dbcursor.fetchall()
    if len(hash_from_table_list)!=0:
        return CompareHash(tablehash=hash_from_table_list[0][1], userenteredkey=password)
    else:
        return 0
    # print(hash_from_table_list)
    # print(hash_from_table_list[0][1])


def AddPassword(username):
    title = str(input('Enter a Title : \n'))
    pwd = str(input('Enter Password associated with Title: \n'))
    # Use the username as Authenticated but unencrypted data
    # enter title, password from user>encrypt password>store 
    tablename = username + 'table'
    ct, key, nonce = EncryptPassword(pwd=pwd, username=username)
    dbcursor.execute(f'''CREATE TABLE IF NOT EXISTS {tablename} (
            title text PRIMARY KEY,
            password text,
            key text,
            nonce text
        )''')
    dbcursor.execute(
        f'''INSERT INTO {tablename} (title, password, key, nonce) VALUES (?,?,?,?)''', (title, ct, key, nonce,))
    dbcon.commit()
    ClearTerminalScreen()
    return 1


def DeletePassword(username):
    #verify user>find pwd to be deleted(if not present, error)>confirm deletion>delete password
    identityResult = ConfirmCredentials()
    if identityResult == 1:
        while True:
            tablename = username + 'table'
            titleOfPwd = str(input('Enter title of password to be deleted : \n'))
            dbcursor.execute(f'''SELECT * FROM {tablename} WHERE title LIKE '%{titleOfPwd}%' ''')
            res = dbcursor.fetchall()
            print(res)
            for i in res:
                if re.match(f"[A-Za-z]*{titleOfPwd}[A-Za-z]*" ,i[0]):
                    print(f'{titleOfPwd} found\n')
                    # handle case where title not present in table
                    confirmation = str(
                        input(f'Are you sure? Enter {i[0]} to confirm\n'))
                    if i[0] == confirmation:
                        dbcursor.execute(
                            f'''DELETE FROM {tablename} WHERE title LIKE '{i[0]}' ''')
                        dbcon.commit()
                        ClearTerminalScreen()
                        print(f'Delete Successful - {i[0]}\n')
                        return 1
                    else:
                        ClearTerminalScreen()
                        print('Operation Cancelled.\n')
                        return 0
                else:
                    ClearTerminalScreen()
                    print(f'{titleOfPwd} not found.\n')
    elif identityResult == 0:
        ClearTerminalScreen()
        print('Incorrect credentials. Please return to Main Menu and try again\n')
        return 0


def DeleteAllPasswords(username):
    #confirm identity>confirm all pwd del>delete complete table
    identityResult = ConfirmCredentials()
    tablename = username + 'table'
    if identityResult == 1:
        while True:
            confirmation = str(
                input(f'Are you sure? Enter {username} to confirm\n'))
            if confirmation == username:
                dbcursor.execute(f'''DELETE FROM {tablename}''')
                dbcon.commit()
                print(f'All passwords deleted - {username}\n')
                return 1
            elif confirmation != username:
                print('Operation cancelled.\n')
                return 0
    elif identityResult == 0:
        print('Incorrect credentials. Please return to Main Menu and try again\n')
        return 0


def UpdateMainPassword(username):
    #verify user>get username,pwd from table>delete username,pwd from table>take new pwd and hash it>store new row of data
    identityResult = ConfirmCredentials()
    if identityResult == 1:
        oldpwd = str(input('Enter current Password: \n'))
        dbcursor.execute(
            f'''SELECT * FROM MainHashManager WHERE username='{username}' ''')
        pwd_from_table = dbcursor.fetchall()
        print(pwd_from_table)
        print(HashPassword(oldpwd))
        if len(pwd_from_table)==0:
            ClearTerminalScreen()
            print('Not found. Try again.\n')
            return 0
        if pwd_from_table[0][1] != HashPassword(oldpwd):
            ClearTerminalScreen()
            print('Wrong password. Try again\n')
            return 0
        else:
            newpwd = str(input('Enter new Password\n'))
            newpwdconf = str(input('Enter new Password again to confirm\n'))
            if newpwd == newpwdconf:
                dbcursor.execute(
                    f'''DELETE FROM MainHashManager WHERE username='{username}' ''')
                dbcursor.execute(f'''INSERT INTO MainHashManager (username, pwdhash) VALUES (?,?)''', (username, HashPassword(newpwd),))
                dbcon.commit()
                ClearTerminalScreen()
                return 1
            else:
                ClearTerminalScreen()
                print('Please try again.\n')
                return 0


def SeeAllPasswords(username):
    #verify user>get full table>display
    identityResult = ConfirmCredentials()
    if identityResult == 1:
        tablename = username + 'table'
        dbcursor.execute(f'''SELECT * FROM {tablename}''')
        full_table = dbcursor.fetchall()
        table = PrettyTable()
        # decryption remaining
        decrypted_pwds = list()
        if len(decrypted_pwds)==0:
            ClearTerminalScreen()
            print('No passwords stored. Add one now!\n')
        for i in full_table:
            decrypted_pwds.append(DecryptPassword(i[2], i[3], i[1], bytes(username, encoding='utf-8')).decode('utf-8'))
        table.field_names = ['Title', 'Password']
        for i in range(len(full_table)):
            table.add_row([full_table[i][0], decrypted_pwds[i]])
        print(table)
        # print(decrypted_pwds)
        ClearTerminalScreen()
        return 1
    else:
        ClearTerminalScreen()
        print('Wrong credentials, please try again.\n')
        return 0


def SeeSinglePassword(username):
    #verify user>find title,pwd in table(error if pwd not there)>display
    identityResult = ConfirmCredentials()
    if identityResult == 1:
        while(True):
            tablename = username + 'table'
            titleOfPwd = str(input('Enter title of password to be found\n'))
            dbcursor.execute(
                f'''SELECT * FROM {tablename} WHERE title LIKE '%{titleOfPwd}%' ''')
            res = dbcursor.fetchall()
            for i in res:
                try:
                    if re.match(f"[A-Za-z]*{titleOfPwd}[A-Za-z]*" ,i[0])==False:
                        ClearTerminalScreen()
                        print('Password not found, please try again\n')
             # decryption remaining
            # print(decrypted_pwd)
                    elif len(res) == 0:
                        ClearTerminalScreen()
                        print('Title does not match. Try again\n')
                    else:
                        ad = bytes(username, encoding='utf-8')
                        print(res)
                        decrypted_pwd = DecryptPassword(key=i[2], nonce=i[3], data=i[1], as_data=bytes(username, encoding='utf-8')).decode('utf-8')
                    table = PrettyTable()
                    table.field_names = ['Title', 'Password']
                    table.add_row([i[0], decrypted_pwd])
                    ClearTerminalScreen()
                    print(table)
                    return 1
                except:
                    print('No match for password found, please try again\n')
    else:
        print('Wrong credentials, please try again.\n')
        return 0

def DeleteAccount(username):
    identityResult = ConfirmCredentials()
    if identityResult == 1:
        confirmation = str(input(f'Are you sure? Enter {username} to confirm\n'))
        if confirmation==username:
            dbcursor.execute(f'''DELETE FROM MainHashManager WHERE username='{username}' ''')
            dbcon.commit()
            ClearTerminalScreen()
            return 1
        else:
            ClearTerminalScreen()
            print('Operation cancelled\n')
            return 0



def UpdatePassword(username):
    # confirm id>check if pwd in table>get old pwd from user and table(decrypt it), delete the row altogether, encrypt new, enter new deets into table
    identityResult = ConfirmCredentials()
    if identityResult == 1:
        while(True):
            tablename = username + 'table'
            titleOfPwd = str(input('Enter title of password to be updated : \n'))
            dbcursor.execute(
                f'''SELECT * FROM {tablename} WHERE title LIKE '%{titleOfPwd}%' ''')
            res = dbcursor.fetchall()
            for i in res:
                if re.match(f"[A-Za-z]*{titleOfPwd}[A-Za-z]*" ,i[0]):
                    oldpwd = DecryptPassword(
                        key=res[0][2], nonce=res[0][3], data=res[0][1], as_data=bytes(username, encoding='utf-8')).decode('utf-8')
                    print(f'Password found - {i[0]} : {oldpwd}')
                    while(True):
                        oldpwduser = str(input('Enter old Password : \n'))
                        newpwd = str(input('Enter new Password : \n'))
                        newpwdconf = str(input('Confirm new Password : \n'))
                        print(newpwd)
                        print(newpwdconf)
                        print(oldpwduser)
                        print(oldpwd)
                        print(type(newpwd))
                        print(type(newpwdconf))
                        print(type(oldpwduser))
                        print(type(oldpwd))
                        if newpwd == newpwdconf and oldpwduser == oldpwd:
                            newpwdhash, key, nonce = EncryptPassword(
                                newpwd, username)
                            dbcursor.execute(
                                f'''DELETE FROM {tablename} WHERE title='{i[0]}' ''')
                            dbcursor.execute(
                                f'''INSERT INTO {tablename} (title, password, key, nonce) VALUES (?,?,?,?)''', (res[0][0], newpwdhash, key, nonce,))
                            dbcon.commit()
                            ClearTerminalScreen()
                            return 1
                        else:
                            ClearTerminalScreen()
                            print('Passwords do not match, try again\n')
                else:
                    ClearTerminalScreen()
                    print('Password title not found. Please try again\n')
        else:
            ClearTerminalScreen()
            print('Wrong credentials, please try again.\n')
            return 0

def MainMenu(username, first_time):
    if first_time==0:
        cprint(figlet_format('Welcome to the Password Manager'), attrs=['bold'])
        print(f'Current user : {username}')
        print('Choose your option')
        print('Press 1 to Search Passwords')
        print('Press 2 to See all registered passwords')
        print('Press 3 to Delete all Passwords')
        print('Press 4 to Delete a Password')
        print('Press 5 to Update a Password')
        print('Press 6 to Update the Main Password')
        print('Press 7 to Add a new Password')
        print('Press 8 to Delete Account')
        ch = int(input())
        if ch==1:
            op = SeeSinglePassword(username)
            if op==1:
                return 1
            elif op==0:
                SeeSinglePassword(username)
                return 1
        elif ch==2:
            op = SeeAllPasswords(username)
            if op==1:
                return 1
            elif op==0:
                SeeAllPasswords(username)
                return 1
        elif ch==3:
            op = DeleteAllPasswords(username)
            if op==1:
                return 1
            elif op==0:
                DeleteAllPasswords(username)
                return 1
        elif ch==4:
            op = DeletePassword(username)
            if op==1:
                return 1
            elif op==0:
                DeletePassword(username)
                return 1
        elif ch==5:
            op = UpdatePassword(username)
            if op==1:
                return 1
            elif op==0:
                UpdatePassword(username)
                return 1
        elif ch==6:
            op = UpdateMainPassword(username)
            if op==1:
                return 1
            elif op==0:
                UpdateMainPassword(username)
                return 1
        elif ch==7:
            op = AddPassword(username)
            if op==1:
                return 1
            elif op==0:
                AddPassword(username)
                return 1
        elif ch==8:
            op = DeleteAccount(username)
            if op==1:
                return 1
            elif op==0:
                DeleteAccount(username)
                return 1
        else:
            print('Wrong option selected')
            return 0
    else:
        cprint(figlet_format('Welcome to the Password Manager'), attrs=['bold'])
        print(f'Current user : {username}')
        print('Choose your option')
        print('Press 1 to Update the Main Password')
        print('Press 2 to Add a new Password')
        print('Press 3 to Delete Account')
        ch = int(input())
        if ch==1:
            op = UpdateMainPassword(username)
            if op==1:
                return 1
            elif op==0:
                UpdateMainPassword(username)
                return 1
        elif ch==2:
            op = AddPassword(username)
            if op==1:
                return 1
            elif op==0:
                AddPassword(username)
                return 1
        elif ch==3:
            op = DeleteAccount(username)
            if op==1:
                return 1
            elif op==0:
                DeleteAccount(username)
                return 1
        else:
            print('Wrong option selected')
            return 0





# MAIN DRIVER CODE STARTS
ch = int(input('Are you a new User?\nJoin now! Press 1 to continue as New User\nAre you a returning User? Log in! Press 2 to continue as Existing User\n\n'))
if ch == 1:
    while True:
        user = str(input('Enter a New Username : \n'))
        dbpwd = str(input('Enter a New Password : \n'))
        dbcursor.execute('''CREATE TABLE IF NOT EXISTS MainHashManager (
                username text PRIMARY KEY,
                pwdhash text
            ) ''')
        pwdhash = HashPassword(dbpwd)
        dbcursor.execute(f'''SELECT * FROM MainHashManager WHERE username='{user}' ''')
        res = dbcursor.fetchall()
        if len(res) == 0:
            dbcursor.execute('''CREATE TABLE IF NOT EXISTS MainHashManager (
                username text PRIMARY KEY,
                pwdhash text  
            ) ''')  # HANDLE CASE WHERE USER ALREADY EXISTS
            # HANDLE CASE WHERE USERNAME ALREADY TAKEN
            dbcursor.execute(
                f'''INSERT INTO MainHashManager (username, pwdhash) VALUES (?,?)''', (user, pwdhash,))
            dbcon.commit()
            print('Credentials Saved! Welcome!')
            while True:
                op = MainMenu(user, 1)
                if op==0:
                    continue
                elif op==1:
                    print('Application quit successfully.')
        elif len(res)!=0:
            print(f'Please choose a different username, {user} is already taken.')
elif ch == 2:
    while True:
        user = str(input('Enter your Username : \n'))
        dbpwd = str(input('Enter your Password : \n'))
        pwdhash = HashPassword(dbpwd)#handle case where user has not made an account yet chooses 21
        dbcursor.execute(f'''SELECT * FROM MainHashManager WHERE username='{user}' ''')
        res = dbcursor.fetchall()
        # print('pwdhash=',pwdhash)
        # print('HashPassword=',res[0][1])
        try:
            if pwdhash==res[0][1]:
                print('Entered')
                while True:
                    op = MainMenu(user, 0)
                    if op==0:
                        continue
                    elif op==1:
                        print('Application quit successfully.\n')
        except:
            print('Except called.')
