import sys
from locker import Locker, Folder, Account
from getpass import getpass
from tabulate import tabulate

l = None
user = None

def main():
    global l
    global user
    print("===============================================")
    print("Multi-User Password Locker - TUI Client - Login")
    print("===============================================")
    server = input("Server: ")
    port = input("Port: ")

    auth_correct = False
    while not auth_correct:
        username = input("Username: ")
        password = getpass("Password: ")

        server = "localhost"
        port = 5000
        # username = "camerongray"
        # password = "password"

        l = Locker(server, int(port), username, password)
        auth_correct = l.check_auth()

        if not auth_correct:
            print("\nIncorrect username/password, please try again!")

    user = l.get_current_user()
    folder_list()

def folder_list():
    while True:
        print("\nFolders:")
        table = []
        for folder in l.get_folders():
            table.append([folder.id, folder.name])
        print(tabulate(table, headers=["ID", "Name"]))
        folder_id = input("ID of folder to view ('q' to quit, 'a' to add "
            "folder): ")

        if folder_id == "q":
            sys.exit()
        elif folder_id == "a":
            folder_name = input("Enter name for folder: ")
            l.add_folder(Folder(folder_name))
        else:
            account_list(folder_id)

def account_list(folder_id):
    while True:
        print("\nAccounts:")
        table = []
        for account in l.get_folder_accounts(folder_id, user.private_key):
            table.append([account.id, account.name, account.username])
        print(tabulate(table, headers=["ID", "Name", "Username"]))
        account_id = input("ID of account to get password for "
            "('b' to go back, 'a' to add an account): ")

        if account_id == "b":
            return
        elif account_id == "a":
            account_name = input("Account name: ")
            account_username = input("Username: ")
            account_password = getpass("Password: ")
            account_notes = input("Notes: ")
            l.add_account(folder_id, Account(
                name = account_name,
                username = account_username,
                password = account_password,
                notes = account_notes
            ))
        else:
            print("Password: {}".format(l.get_account_password(account_id,
                user.private_key)))

if __name__ == "__main__":
    main()
