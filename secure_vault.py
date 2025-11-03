import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog, scrolledtext
import os
import json
import base64
import datetime
import io  # Added for in-memory file handling

# --- New Imports for Added Features ---
try:
    # For Google Drive
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
    from google.auth.transport.requests import Request
    from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload

    # For File Preview
    from PIL import Image, ImageTk

    # For File Sharing
    import qrcode
except ImportError:
    messagebox.showerror(
        "Missing Libraries",
        "Required libraries are missing. Please run:\n\n"
        "pip install google-api-python-client google-auth-oauthlib google-auth-httplib2 Pillow qrcode"
    )
    exit()

# --- Cryptography Imports ---
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

# --- Constants ---
VAULT_FILENAME = "vault.dat"
SALT_SIZE = 16
NONCE_SIZE = 12  # AES-GCM recommended nonce size
KEY_SIZE = 32    # AES 256
PBKDF2_ITERATIONS = 600000  # Increased for better security (OWASP recommendation)
MAX_LOGIN_ATTEMPTS = 3

# --- Google Drive Constants ---
CLIENT_SECRET_FILE = 'client_secret.json'
TOKEN_FILE = 'token.json'
# Scopes: This will only grant access to files created by this app.
DRIVE_SCOPES = ['https://www.googleapis.com/auth/drive.file']
DRIVE_VAULT_FILENAME = 'vault.dat' # The name of the file on Google Drive


class SecureVaultApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Vault")
        self.root.geometry("500x400")
        self.root.resizable(False, False)

        # App state
        self.master_key = None
        self.vault_salt = None
        self.vault_contents = {"files": {}, "logs": []}
        self.failed_attempts = 0

        # --- New State Variables ---
        self.drive_service = None
        self.preview_window = None # To manage preview popups
        self.qr_window = None      # To manage QR code popups

        # Style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TButton', padding=6, relief="flat", font=('Inter', 10, 'bold'))
        self.style.configure('TLabel', font=('Inter', 10))
        self.style.configure('TEntry', padding=5)
        self.style.configure('Header.TLabel', font=('Inter', 16, 'bold'))
        self.style.configure('Error.TButton', foreground='red')

        # Main frame
        self.main_frame = ttk.Frame(root, padding="20 20 20 20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.check_vault_exists()

    def check_vault_exists(self):
        """Checks if the vault file exists and shows the appropriate screen."""
        if os.path.exists(VAULT_FILENAME):
            self.show_login_screen()
        else:
            self.show_create_vault_screen()

    def clear_frame(self):
        """Destroys all widgets in the main frame."""
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    # --- Key Derivation and Crypto ---

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derives a 32-byte key from a password and salt using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS
        )
        return kdf.derive(password.encode('utf-8'))

    def save_vault(self):
        """Encrypts and saves the entire vault_contents to disk."""
        if not self.master_key or not self.vault_salt:
            messagebox.showerror("Error", "Vault is not properly initialized.")
            return False

        try:
            # Serialize vault contents
            data_to_encrypt = json.dumps(self.vault_contents).encode('utf-8')

            # Encrypt the entire vault blob
            aesgcm = AESGCM(self.master_key)
            nonce = os.urandom(NONCE_SIZE)
            ciphertext_with_tag = aesgcm.encrypt(nonce, data_to_encrypt, None)

            # Write to file: salt + nonce + encrypted_data
            with open(VAULT_FILENAME, 'wb') as f:
                f.write(self.vault_salt)
                f.write(nonce)
                f.write(ciphertext_with_tag)
            return True
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save vault: {e}")
            return False

    def load_vault(self, password: str) -> bool:
        """Loads and decrypts the vault file using the provided password."""
        try:
            with open(VAULT_FILENAME, 'rb') as f:
                # Read components: salt(16) + nonce(12) + data
                self.vault_salt = f.read(SALT_SIZE)
                if len(self.vault_salt) < SALT_SIZE:
                    raise ValueError("Vault file is corrupted (invalid salt).")
                
                nonce = f.read(NONCE_SIZE)
                if len(nonce) < NONCE_SIZE:
                    raise ValueError("Vault file is corrupted (invalid nonce).")
                
                ciphertext_with_tag = f.read()

            # Derive key
            self.master_key = self.derive_key(password, self.vault_salt)
            
            # Decrypt
            aesgcm = AESGCM(self.master_key)
            decrypted_data = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
            
            # Load contents
            self.vault_contents = json.loads(decrypted_data.decode('utf-8'))
            return True
        except (FileNotFoundError, IOError):
            messagebox.showerror("Error", "Vault file not found.")
            return False
        except InvalidTag:
            # This is the expected error for a wrong password
            self.master_key = None # Clear bad key
            self.vault_salt = None
            return False
        except Exception as e:
            messagebox.showerror("Load Error", f"Failed to load vault: {e}")
            self.master_key = None
            self.vault_salt = None
            return False

    def log_activity(self, message: str):
        """Adds a timestamped log entry to the vault."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if "logs" not in self.vault_contents:
            self.vault_contents["logs"] = []
        self.vault_contents["logs"].append(f"{now}: {message}")
        # Note: save_vault() must be called after this to persist the log.

    # --- GUI Screens ---

    def show_create_vault_screen(self):
        """Displays the UI for creating a new vault and password."""
        self.clear_frame()
        self.root.geometry("500x400")
        
        ttk.Label(self.main_frame, text="Create New Vault", style='Header.TLabel').pack(pady=20)
        
        ttk.Label(self.main_frame, text="Create a strong master password:").pack(pady=(10, 5))
        
        self.password_entry = ttk.Entry(self.main_frame, show="*")
        self.password_entry.pack(pady=5, padx=20, fill=tk.X)
        self.password_entry.focus()
        
        ttk.Label(self.main_frame, text="Confirm password:").pack(pady=(10, 5))
        
        self.confirm_password_entry = ttk.Entry(self.main_frame, show="*")
        self.confirm_password_entry.pack(pady=5, padx=20, fill=tk.X)

        self.create_button = ttk.Button(
            self.main_frame, 
            text="Create Vault", 
            command=self.handle_create_vault
        )
        self.create_button.pack(pady=30)
        
        self.root.bind('<Return>', lambda e: self.create_button.invoke())

        # --- Add Drive Restore button ---
        drive_frame = ttk.Frame(self.main_frame)
        drive_frame.pack(side=tk.BOTTOM, pady=20)
        ttk.Label(drive_frame, text="Already have a vault?").pack(side=tk.LEFT, padx=5)
        ttk.Button(
            drive_frame,
            text="Restore from Google Drive",
            command=self.handle_drive_download
        ).pack(side=tk.LEFT)


    def show_login_screen(self):
        """Displays the UI for logging into an existing vault."""
        self.clear_frame()
        self.root.geometry("500x400")
        
        ttk.Label(self.main_frame, text="Secure Vault Login", style='Header.TLabel').pack(pady=20)
        
        ttk.Label(self.main_frame, text="Enter master password:").pack(pady=(10, 5))
        
        self.password_entry = ttk.Entry(self.main_frame, show="*")
        self.password_entry.pack(pady=5, padx=20, fill=tk.X)
        self.password_entry.focus()

        self.login_button = ttk.Button(
            self.main_frame, 
            text="Login", 
            command=self.handle_login
        )
        self.login_button.pack(pady=30)
        
        self.root.bind('<Return>', lambda e: self.login_button.invoke())

        # --- Add Drive Restore button ---
        drive_frame = ttk.Frame(self.main_frame)
        drive_frame.pack(side=tk.BOTTOM, pady=20)
        ttk.Label(drive_frame, text="Restore backup?").pack(side=tk.LEFT, padx=5)
        ttk.Button(
            drive_frame,
            text="Restore from Google Drive",
            command=self.handle_drive_download
        ).pack(side=tk.LEFT)

    def show_main_vault_screen(self):
        """Displays the main vault interface for file management."""
        self.clear_frame()
        self.root.geometry("750x500") # Resize for main view
        self.root.resizable(True, True) # Allow resizing
        
        # --- Top Frame for Buttons ---
        top_frame = ttk.Frame(self.main_frame)
        top_frame.pack(fill=tk.X, pady=(10,0))
        
        # --- File Operations ---
        file_ops_frame = ttk.LabelFrame(top_frame, text="File Operations", padding=10)
        file_ops_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        ttk.Button(file_ops_frame, text="Add File", command=self.handle_add_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_ops_frame, text="Export File", command=self.handle_export_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_ops_frame, text="Share File", command=self.handle_share_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_ops_frame, text="Import Shared", command=self.handle_import_shared_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_ops_frame, text="Delete File", style='Error.TButton', command=self.handle_delete_file).pack(side=tk.LEFT, padx=5)

        # --- Vault Operations ---
        vault_ops_frame = ttk.LabelFrame(top_frame, text="Vault", padding=10)
        vault_ops_frame.pack(side=tk.RIGHT, fill=tk.X, padx=5)

        ttk.Button(vault_ops_frame, text="View Logs", command=self.handle_view_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(vault_ops_frame, text="Lock Vault", command=self.handle_lock_vault).pack(side=tk.LEFT, padx=5)

        # --- Google Drive Frame ---
        drive_frame = ttk.LabelFrame(self.main_frame, text="Cloud Backup (Google Drive)", padding=10)
        drive_frame.pack(fill=tk.X, pady=10, padx=5)
        ttk.Button(drive_frame, text="Backup Vault to Drive", command=self.handle_drive_backup).pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        ttk.Button(drive_frame, text="Restore Vault from Drive", command=self.handle_drive_download).pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        
        # --- File List ---
        list_frame = ttk.Frame(self.main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=10, padx=5)
        
        ttk.Label(list_frame, text="Vault Files (Double-click to preview):").pack(anchor=tk.W)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL)
        self.file_listbox = tk.Listbox(
            list_frame, 
            yscrollcommand=scrollbar.set, 
            font=('Inter', 11),
            height=15
        )
        scrollbar.config(command=self.file_listbox.yview)
        
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # --- Bind Preview ---
        self.file_listbox.bind("<Double-1>", self.handle_preview_file)

        self.update_file_list()

    def update_file_list(self):
        """Refreshes the file listbox with files from vault_contents."""
        if not hasattr(self, 'file_listbox'):
            return # Don't update if listbox doesn't exist yet

        self.file_listbox.delete(0, tk.END)
        files = sorted(self.vault_contents.get("files", {}).keys())
        if not files:
            self.file_listbox.insert(tk.END, "  Vault is empty. Click 'Add File' to start.")
            self.file_listbox.config(state=tk.DISABLED)
        else:
            self.file_listbox.config(state=tk.NORMAL)
            for filename in files:
                self.file_listbox.insert(tk.END, f"  {filename}")

    # --- Button Handlers ---

    def handle_create_vault(self):
        """Validates and creates a new vault file."""
        password = self.password_entry.get()
        confirm = self.confirm_password_entry.get()
        
        if not password or not confirm:
            messagebox.showwarning("Input Error", "Password fields cannot be empty.")
            return
            
        if password != confirm:
            messagebox.showwarning("Input Error", "Passwords do not match.")
            return
        
        if len(password) < 12:
             if not messagebox.askyesno("Weak Password", "Password is less than 12 characters. This is not recommended.\n\nContinue anyway?"):
                 return

        # Create vault
        self.vault_salt = os.urandom(SALT_SIZE)
        self.master_key = self.derive_key(password, self.vault_salt)
        self.vault_contents = {"files": {}, "logs": []}
        self.log_activity("Vault created.")
        
        if self.save_vault():
            messagebox.showinfo("Success", "Vault created successfully.")
            self.show_main_vault_screen()
        else:
            messagebox.showerror("Error", "Could not save vault file to disk. Check permissions.")
            self.master_key = None
            self.vault_salt = None


    def handle_login(self):
        """Validates login credentials and handles lockout."""
        password = self.password_entry.get()
        
        if not password:
            messagebox.showwarning("Input Error", "Password cannot be empty.")
            return

        if self.load_vault(password):
            self.failed_attempts = 0
            # messagebox.showinfo("Login Success", "Welcome back.") # A bit annoying, remove
            self.log_activity("User logged in.")
            self.save_vault() # Save the new log entry
            self.show_main_vault_screen()
        else:
            # load_vault() already showed an error if it was a file issue
            # If it was an InvalidTag, it just returns False silently.
            if self.master_key is None: # This means load_vault failed for crypto reasons
                self.failed_attempts += 1
                remaining = MAX_LOGIN_ATTEMPTS - self.failed_attempts
                if remaining > 0:
                    messagebox.showwarning("Login Failed", f"Invalid password. {remaining} attempts remaining.")
                else:
                    messagebox.showerror("Vault Locked", "Too many failed login attempts. The application will now close.")
                    self.root.destroy()

    def handle_add_file(self):
        """Opens file dialog, adds file, encrypts, and asks to delete original."""
        if not self.master_key:
            messagebox.showerror("Error", "Vault is locked.")
            return

        filepaths = filedialog.askopenfilenames() # Allow multiple files
        if not filepaths:
            return
            
        added_count = 0
        for filepath in filepaths:
            filename = os.path.basename(filepath)
            if filename in self.vault_contents["files"]:
                if not messagebox.askyesno("Overwrite", f"'{filename}' already exists. Overwrite?"):
                    continue

            try:
                # Read the file content
                with open(filepath, 'rb') as f:
                    file_content = f.read()

                # Encrypt file content
                aesgcm = AESGCM(self.master_key)
                nonce = os.urandom(NONCE_SIZE)
                encrypted_content = aesgcm.encrypt(nonce, file_content, None)
                
                # Store as base64: nonce + encrypted_data
                stored_data = base64.b64encode(nonce + encrypted_content).decode('utf-8')
                
                # Add to in-memory vault
                self.vault_contents["files"][filename] = stored_data
                self.log_activity(f"Added file: {filename}")
                added_count += 1
                
            except Exception as e:
                messagebox.showerror("Add File Error", f"Failed to add file '{filename}': {e}")
        
        if added_count > 0:
            # Save vault once after all files are added
            self.save_vault()
            self.update_file_list()
            messagebox.showinfo("Success", f"{added_count} file(s) added to vault.")

            # Ask to delete *all* added originals
            if messagebox.askyesno("Delete Original Files?",
                                f"{added_count} file(s) were successfully added to the vault.\n\n"
                                "Do you want to permanently delete the original file(s) from your disk?"):
                for filepath in filepaths:
                    try:
                        os.remove(filepath)
                        self.log_activity(f"Deleted original file from disk: {os.path.basename(filepath)}")
                    except Exception as e:
                        messagebox.showerror("Delete Error", f"Could not delete original file: {filepath}\n{e}")
                self.save_vault() # Save the new log entries

    def _get_selected_filename(self):
        """Helper to get the currently selected filename from the listbox."""
        try:
            selected_index = self.file_listbox.curselection()
            if not selected_index:
                messagebox.showwarning("No Selection", "Please select a file first.")
                return None
            
            # Get filename and strip leading spaces
            filename = self.file_listbox.get(selected_index).strip()
            
            # Check if it's the "empty" message
            if filename.startswith("Vault is empty"):
                return None

            return filename
        except tk.TclError:
             messagebox.showwarning("No Selection", "Please select a file first.")
             return None

    def _decrypt_file_from_vault(self, filename: str):
        """Helper to decrypt a file from vault contents. Returns None on error."""
        if not self.master_key:
            messagebox.showerror("Error", "Vault is locked.")
            return None
        
        try:
            # Retrieve and decode
            b64_data = self.vault_contents["files"][filename]
            full_data = base64.b64decode(b64_data)
            
            # Split nonce and ciphertext
            nonce = full_data[:NONCE_SIZE]
            encrypted_content = full_data[NONCE_SIZE:]
            
            # Decrypt
            aesgcm = AESGCM(self.master_key)
            decrypted_content = aesgcm.decrypt(nonce, encrypted_content, None)
            
            return decrypted_content
        except KeyError:
            messagebox.showerror("Error", f"File '{filename}' not found in vault data.")
            return None
        except Exception as e:
            messagebox.showerror("Decrypt Error", f"Failed to decrypt file: {e}")
            return None


    def handle_export_file(self):
        """Decrypts a selected file and saves it to disk."""
        filename = self._get_selected_filename()
        if not filename:
            return

        save_path = filedialog.asksaveasfilename(initialfile=filename)
        if not save_path:
            return

        decrypted_content = self._decrypt_file_from_vault(filename)
        if decrypted_content is None:
            return # Error already shown

        try:
            # Write to disk
            with open(save_path, 'wb') as f:
                f.write(decrypted_content)
                
            self.log_activity(f"Exported file: {filename}")
            self.save_vault() # Save log
            messagebox.showinfo("Success", f"'{filename}' exported successfully.")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to save exported file: {e}")

    def handle_delete_file(self):
        """Removes a selected file from the vault."""
        filename = self._get_selected_filename()
        if not filename:
            return

        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to permanently delete '{filename}' from the vault?"):
            try:
                del self.vault_contents["files"][filename]
                self.log_activity(f"Deleted file: {filename}")
                self.save_vault()
                self.update_file_list()
                messagebox.showinfo("Deleted", f"'{filename}' has been deleted.")
            except Exception as e:
                messagebox.showerror("Delete Error", f"Failed to delete file: {e}")

    def handle_view_logs(self):
        """Displays the access and activity logs in a new window."""
        log_window = tk.Toplevel(self.root)
        log_window.title("Activity Logs")
        log_window.geometry("600x400")
        
        log_text = scrolledtext.ScrolledText(log_window, wrap=tk.WORD, font=('Monaco', 10))
        log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        log_text.insert(tk.END, "--- Secure Vault Activity Log ---\n\n")
        
        if self.vault_contents.get("logs"):
            for entry in reversed(self.vault_contents["logs"]):
                log_text.insert(tk.END, f"{entry}\n")
        else:
            log_text.insert(tk.END, "No activity to display.")
            
        log_text.config(state=tk.DISABLED) # Make read-only
        
        # Log this action
        self.log_activity("Viewed activity logs.")
        self.save_vault()

    def handle_lock_vault(self):
        """Locks the vault, clears memory, and returns to login screen."""
        # Clear sensitive data from memory
        self.master_key = None
        self.vault_contents = {"files": {}, "logs": []}
        self.vault_salt = None
        
        # Clear Drive service
        self.drive_service = None

        # Close any open preview/QR windows
        if self.preview_window and self.preview_window.winfo_exists():
            self.preview_window.destroy()
        if self.qr_window and self.qr_window.winfo_exists():
            self.qr_window.destroy()

        # Reset UI
        self.root.resizable(False, False) # Lock resizing again
        self.show_login_screen()

    # --- Feature 1: Google Drive Backup/Sync ---

    def _get_drive_service(self):
        """Authenticates and returns the Google Drive API service object."""
        if self.drive_service:
            return self.drive_service

        creds = None
        # The file token.json stores the user's access and refresh tokens.
        if os.path.exists(TOKEN_FILE):
            try:
                creds = Credentials.from_authorized_user_file(TOKEN_FILE, DRIVE_SCOPES)
            except Exception as e:
                print(f"Error loading token.json: {e}")
                creds = None

        # If there are no (valid) credentials available, let the user log in.
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                except Exception as e:
                    messagebox.showerror("Auth Error", f"Could not refresh token: {e}\nPlease re-authenticate.")
                    os.remove(TOKEN_FILE)
                    creds = None # Force re-login
            else:
                try:
                    flow = InstalledAppFlow.from_client_secrets_file(
                        CLIENT_SECRET_FILE, DRIVE_SCOPES)
                    creds = flow.run_local_server(port=0)
                except FileNotFoundError:
                    messagebox.showerror("Auth Error", f"Client secret file not found: {CLIENT_SECRET_FILE}")
                    return None
                except Exception as e:
                    messagebox.showerror("Auth Error", f"Authentication failed: {e}")
                    return None
            
            # Save the credentials for the next run
            try:
                with open(TOKEN_FILE, 'w') as token:
                    token.write(creds.to_json())
            except Exception as e:
                messagebox.showwarning("Token Error", f"Could not save auth token: {e}")

        try:
            service = build('drive', 'v3', credentials=creds)
            self.drive_service = service
            return service
        except Exception as e:
            messagebox.showerror("API Error", f"Failed to build Drive service: {e}")
            return None

    def _find_drive_vault_id(self, service):
        """Finds the file ID of 'vault.dat' on Google Drive."""
        try:
            # search for files created by this app, with the specific name
            response = service.files().list(
                q=f"name='{DRIVE_VAULT_FILENAME}'",
                spaces='drive',
                fields='files(id, name)').execute()
            
            files = response.get('files', [])
            if not files:
                return None # No file found
            
            return files[0].get('id') # Return ID of the first match
        except HttpError as e:
            messagebox.showerror("Drive Error", f"Could not search for vault: {e}")
            return None

    def handle_drive_backup(self):
        """Encrypts and backs up the vault to Google Drive."""
        if not self.master_key:
            messagebox.showerror("Error", "Vault is locked. Cannot back up.")
            return

        if not messagebox.askyesno("Confirm Backup", "This will upload your encrypted vault to Google Drive. Proceed?"):
            return

        # Ensure local vault is saved first
        if not self.save_vault():
            messagebox.showerror("Save Error", "Could not save local vault. Backup aborted.")
            return

        service = self._get_drive_service()
        if not service:
            return

        file_id = self._find_drive_vault_id(service)
        
        media = MediaFileUpload(VAULT_FILENAME, mimetype='application/octet-stream', resumable=True)
        
        try:
            if file_id:
                # File exists, update it
                service.files().update(fileId=file_id, media_body=media).execute()
                messagebox.showinfo("Backup Success", "Vault successfully updated on Google Drive.")
                self.log_activity("Vault backed up to Google Drive (updated).")
            else:
                # File doesn't exist, create it
                file_metadata = {'name': DRIVE_VAULT_FILENAME}
                service.files().create(body=file_metadata, media_body=media, fields='id').execute()
                messagebox.showinfo("Backup Success", "Vault successfully backed up to Google Drive (created).")
                self.log_activity("Vault backed up to Google Drive (created).")
            
            self.save_vault() # Save the new log
        except HttpError as e:
            messagebox.showerror("Backup Error", f"An error occurred during backup: {e}")
        except Exception as e:
            messagebox.showerror("Backup Error", f"An unexpected error occurred: {e}")

    def handle_drive_download(self):
        """Downloads and restores the vault from Google Drive."""
        if messagebox.askyesno("Confirm Restore",
                                "This will OVERWRITE your local vault file with the version from Google Drive.\n\n"
                                "ARE YOU SURE YOU WANT TO PROCEED?"):
            
            service = self._get_drive_service()
            if not service:
                return

            file_id = self._find_drive_vault_id(service)
            if not file_id:
                messagebox.showerror("Restore Error", "No vault file found on your Google Drive.")
                return

            try:
                request = service.files().get_media(fileId=file_id)
                fh = io.BytesIO()
                downloader = MediaIoBaseDownload(fh, request)
                
                done = False
                while done is False:
                    status, done = downloader.next_chunk()
                    # print(f"Download {int(status.progress() * 100)}%.") # Debug

                # Save the downloaded data to the local vault file
                with open(VAULT_FILENAME, 'wb') as f:
                    f.write(fh.getvalue())

                messagebox.showinfo("Restore Success", "Vault successfully restored from Google Drive.\n\nThe app will now lock. Please log in again.")
                # Force lock/re-login to load the new vault
                self.handle_lock_vault()

            except HttpError as e:
                messagebox.showerror("Restore Error", f"An error occurred during restore: {e}")
            except Exception as e:
                messagebox.showerror("Restore Error", f"An unexpected error occurred: {e}")

    # --- Feature 2: File Preview ---

    def handle_preview_file(self, event=None):
        """Shows an in-memory preview of a text or image file."""
        filename = self._get_selected_filename()
        if not filename:
            return

        decrypted_content = self._decrypt_file_from_vault(filename)
        if decrypted_content is None:
            return

        # Close previous preview window if it exists
        if self.preview_window and self.preview_window.winfo_exists():
            self.preview_window.destroy()

        self.preview_window = tk.Toplevel(self.root)
        self.preview_window.title(f"Preview: {filename}")
        
        file_ext = os.path.splitext(filename)[1].lower()

        # Level 1: Text Preview
        if file_ext in ('.txt', '.md', '.py', '.json', '.xml', '.html', '.css', '.js', '.log'):
            try:
                text_content = decrypted_content.decode('utf-8')
                self.preview_window.geometry("700x500")
                txt = scrolledtext.ScrolledText(self.preview_window, wrap=tk.WORD, font=('Monaco', 10))
                txt.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                txt.insert(tk.END, text_content)
                txt.config(state=tk.DISABLED)
            except UnicodeDecodeError:
                messagebox.showwarning("Preview Error", "File has a text-like extension but could not be decoded as UTF-8 text.")
                self.preview_window.destroy()
            except Exception as e:
                messagebox.showerror("Preview Error", f"Could not preview text: {e}")
                self.preview_window.destroy()

        # Level 2: Image Preview
        elif file_ext in ('.png', '.jpg', '.jpeg', '.gif', '.bmp'):
            try:
                img_data = io.BytesIO(decrypted_content)
                img = Image.open(img_data)
                
                # Resize large images to fit screen (max 800x600)
                max_w, max_h = 800, 600
                img.thumbnail((max_w, max_h), Image.Resampling.LANCZOS)
                
                photo = ImageTk.PhotoImage(img)

                self.preview_window.geometry(f"{photo.width()}x{photo.height()}")
                self.preview_window.resizable(False, False)

                lbl = ttk.Label(self.preview_window, image=photo)
                lbl.image = photo # Keep a reference!
                lbl.pack(fill=tk.BOTH, expand=True)

            except Exception as e:
                messagebox.showerror("Preview Error", f"Could not preview image: {e}")
                self.preview_window.destroy()

        # Unsupported
        else:
            messagebox.showinfo("Preview", f"Preview is not supported for '{file_ext}' files.\n\nPlease export the file to view it.")
            self.preview_window.destroy()


    # --- Feature 3: Encrypted File Sharing ---
    
    def handle_share_file(self):
        """Exports a single file, re-encrypted with a new key shown as a QR code."""
        filename = self._get_selected_filename()
        if not filename:
            return

        # 1. Decrypt file using master key
        decrypted_content = self._decrypt_file_from_vault(filename)
        if decrypted_content is None:
            return # Error already shown

        try:
            # 2. Generate new one-time key and nonce
            share_key = os.urandom(KEY_SIZE)  # 32 bytes
            share_nonce = os.urandom(NONCE_SIZE) # 12 bytes

            # 3. Re-encrypt content with new key
            aesgcm = AESGCM(share_key)
            encrypted_content = aesgcm.encrypt(share_nonce, decrypted_content, None)

            # 4. Ask user where to save the shareable file
            save_path = filedialog.asksaveasfilename(
                initialfile=f"{filename}.shared",
                title="Save Shareable File As",
                filetypes=[("Shared Vault File", "*.shared"), ("All Files", "*.*")]
            )
            if not save_path:
                return # User cancelled

            # 5. Save the new encrypted file
            # Note: We save NONCE + ENCRYPTED_CONTENT (same as vault files)
            with open(save_path, 'wb') as f:
                f.write(share_nonce)
                f.write(encrypted_content)

            # 6. Combine key and nonce for the QR code
            # Key (32) + Nonce (12) = 44 bytes
            key_data = share_key + share_nonce
            
            # 7. Base64-encode this combo
            b64_key_data = base64.b64encode(key_data).decode('utf-8')
            
            # 8. Generate and display QR code
            self.show_share_qr(b64_key_data, filename)

            messagebox.showinfo("File Ready to Share",
                                f"'{os.path.basename(save_path)}' was saved.\n\n"
                                f"Give this file to your contact, and have them scan the QR code to get the key.")

        except Exception as e:
            messagebox.showerror("Share Error", f"Could not create shared file: {e}")

    def show_share_qr(self, key_data: str, filename: str):
        """Displays a new window with the QR code for the key."""
        if self.qr_window and self.qr_window.winfo_exists():
            self.qr_window.destroy()
        
        self.qr_window = tk.Toplevel(self.root)
        self.qr_window.title(f"Share Key for {filename}")
        self.qr_window.resizable(False, False)

        try:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(key_data)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert PIL image for Tkinter
            photo = ImageTk.PhotoImage(img)
            
            ttk.Label(self.qr_window, text=f"Scan to import '{filename}'", font=('Inter', 12, 'bold')).pack(pady=10)
            
            lbl = ttk.Label(self.qr_window, image=photo)
            lbl.image = photo # Keep reference
            lbl.pack(padx=20, pady=10)

            # Show the raw key string in case QR scan fails
            ttk.Label(self.qr_window, text="Or, copy/paste this key data:").pack(pady=(10,0))
            key_entry = ttk.Entry(self.qr_window, font=('Monaco', 9), width=70)
            key_entry.insert(0, key_data)
            key_entry.config(state="readonly")
            key_entry.pack(padx=20, pady=10)

        except Exception as e:
            messagebox.showerror("QR Error", f"Could not generate QR code: {e}", parent=self.qr_window)


    def handle_import_shared_file(self):
        """Imports a .shared file using a key from the user."""
        if not self.master_key:
            messagebox.showerror("Error", "Vault is locked.")
            return

        # 1. Ask for the .shared file
        filepath = filedialog.askopenfilename(
            title="Select Shared File to Import",
            filetypes=[("Shared Vault File", "*.shared"), ("All Files", "*.*")]
        )
        if not filepath:
            return

        # 2. Ask for the key data (from QR scan)
        key_data = simpledialog.askstring(
            "Import Key",
            "Please scan the QR code and paste the resulting key data here:",
            parent=self.root
        )
        if not key_data:
            return

        try:
            # 3. Decode the key data
            key_and_nonce = base64.b64decode(key_data)
            if len(key_and_nonce) != (KEY_SIZE + NONCE_SIZE):
                raise ValueError(f"Invalid key data length. Expected {KEY_SIZE + NONCE_SIZE} bytes.")

            share_key = key_and_nonce[:KEY_SIZE]
            share_nonce = key_and_nonce[KEY_SIZE:]

            # 4. Read the encrypted file
            with open(filepath, 'rb') as f:
                # The file format is NONCE + ENCRYPTED_CONTENT
                # But the *real* nonce is the one from the QR code!
                # The nonce in the file is a red herring from the old design.
                # Let's re-read the handle_share_file...
                # Ah, `f.write(share_nonce)` - okay, so the nonce IS in the file.
                # Let's check `handle_share_file` again.
                # Line 912: `f.write(share_nonce)`
                # Line 918: `key_data = share_key + share_nonce`
                # This is redundant! The nonce is shared twice.
                # Let's fix this.
                
                # --- FIXING THE SHARE LOGIC ---
                # `handle_share_file` should *only* put the KEY in the QR code.
                # The NONCE should be saved *with the file*.
                # This is more standard.
                
                # Let's correct this in real-time.
                # This function (`handle_import_shared_file`) will assume the
                # *old* (flawed) logic: QR code has key+nonce, file has nonce+data.
                # And I will correct `handle_share_file` to match.
                
                # OK, wait, my logic was confused.
                # `handle_share_file` (line 912) saves: `share_nonce + encrypted_content`
                # `handle_share_file` (line 918) encodes: `share_key + share_nonce`
                
                # This means the QR code has the key *and* the nonce.
                # The file *also* has the nonce. This is fine, if redundant.
                # The `share_nonce` from the QR code is the *correct* one to use.
                
                file_nonce = f.read(NONCE_SIZE)
                encrypted_content = f.read()
                
                if file_nonce != share_nonce:
                    messagebox.showwarning("Import Warning", "Nonce in file does not match nonce from key data. Proceeding with key data.")

            # 5. Decrypt using the shared key and nonce
            aesgcm = AESGCM(share_key)
            decrypted_content = aesgcm.decrypt(share_nonce, encrypted_content, None)

            # 6. Ask what to name the file in the vault
            original_filename = os.path.basename(filepath).replace(".shared", "")
            filename = simpledialog.askstring(
                "Save to Vault",
                "Enter a name for the imported file:",
                initialvalue=original_filename,
                parent=self.root
            )
            if not filename:
                return # User cancelled

            if filename in self.vault_contents["files"]:
                if not messagebox.askyesno("Overwrite", f"'{filename}' already exists in your vault. Overwrite?"):
                    return
            
            # 7. Add the decrypted content to the vault
            # (It will be re-encrypted with the *master_key* when added)
            
            # Encrypt with *master* key
            aesgcm_master = AESGCM(self.master_key)
            master_nonce = os.urandom(NONCE_SIZE)
            master_encrypted_content = aesgcm_master.encrypt(master_nonce, decrypted_content, None)
            
            # Store as base64
            stored_data = base64.b64encode(master_nonce + master_encrypted_content).decode('utf-8')
            
            # Add to in-memory vault
            self.vault_contents["files"][filename] = stored_data
            
            # 8. Log and save
            self.log_activity(f"Imported shared file: {filename}")
            self.save_vault()
            self.update_file_list()
            messagebox.showinfo("Success", f"'{filename}' was successfully imported into your vault.")

        except (InvalidTag):
            messagebox.showerror("Import Error", "Invalid key data. Could not decrypt file.")
        except (ValueError, TypeError, base64.binascii.Error) as e:
            messagebox.showerror("Import Error", f"Invalid key data format: {e}")
        except Exception as e:
            messagebox.showerror("Import Error", f"Failed to import file: {e}")


# --- Main execution ---
if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = SecureVaultApp(root)
        root.mainloop()
    except Exception as e:
        # Fallback for unexpected errors
        print(f"A critical error occurred: {e}")
        # Try to show a simple tkinter error box if root is still available
        try:
            messagebox.showerror("Critical Error", f"A critical error occurred: {e}\n\nThe application will close.")
        except:
            pass
