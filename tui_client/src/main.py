import sys
from locker import Locker
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
        folder_id = input("ID of folder to view (or 'q' to quit): ")

        if folder_id == "q":
            sys.exit()

        account_list(folder_id)

def account_list(folder_id):
    while True:
        print("\nAccounts:")
        table = []
        for account in l.get_folder_accounts(folder_id, user.private_key):
            table.append([account.id, account.name, account.username])
        print(tabulate(table, headers=["ID", "Name", "Username"]))
        account_id = input("ID of account to get password for "
            "(or 'b' to go back): ")

        if account_id == "b":
            return

        print("Password: {}".format(l.get_account_password(account_id,
            user.private_key)))

if __name__ == "__main__":
    main()
