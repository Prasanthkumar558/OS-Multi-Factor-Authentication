import sys
import getpass
from auth_module import SecureAuthModule

def display_menu():
    print("\n--- OS Secure Authentication Module Simulator ---")
    print("1. Register a new user")
    print("2. Login (Password + MFA)")
    print("3. Exit")
    return input("Select an option: ")

def main():
    print("Initializing Secure Auth Module...")
    # Intentionally storing DB locally for the simulation
    auth = SecureAuthModule()
    
    while True:
        choice = display_menu()
        
        if choice == '1':
            print("\n-- User Registration --")
            username = input("Enter new username: ")
            password = getpass.getpass("Enter new secure password: ")
            
            success, message = auth.register_user(username, password)
            if success:
                print("\n[SUCCESS] " + message)
            else:
                print("\n[ERROR] " + message)
                
        elif choice == '2':
            print("\n-- System Login --")
            username = input("Username: ")
            password = getpass.getpass("Password: ")
            
            # Step 1: Password Auth
            success, message = auth.authenticate_step_1(username, password)
            
            if success:
                print("Password OK. MFA required.")
                mfa_token = input("Enter 6-digit MFA Token: ")
                
                # Step 2: MFA
                if auth.authenticate_step_2_mfa(username, mfa_token):
                    print(f"\n[GRANTED] Welcome to the System, '{username}'! Authentication successful.")
                else:
                    print("\n[DENIED] Invalid MFA Token. Access Denied.")
            else:
                print(f"\n[DENIED] {message}")
                
        elif choice == '3':
            print("Exiting...")
            sys.exit(0)
            
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
