import json
import os
import base64
import secrets
import time
import io
import re
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from tkinter.scrolledtext import ScrolledText

# Crypto / KDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from argon2.low_level import hash_secret_raw, Type

# TOTP & QR
import pyotp
import qrcode
from PIL import Image, ImageTk

# -----------------------
# Config / Constants
# -----------------------
VAULT_FILENAME = "vault.json"
AUDIT_FILENAME = "audit.log"
SALT_BYTES = 16
KDF_TIME_COST = 2
KDF_MEMORY_COST = 65536  # 64 MiB
KDF_PARALLELISM = 1
KDF_HASH_LEN = 32
AEAD_NONCE_SIZE = 12
SENTINEL_SITE = "__meta__"
TOTP_FIELD = "totp"  # vault top-level field storing encrypted totp secret

# Master password policy
MIN_LENGTH = 12
SPECIAL_CHARS = r"!@#$%^&*()_+\-=\[\]{};':\",.<>\/?`~"

# -----------------------
# Helpers
# -----------------------
def b64(v: bytes) -> str:
    return base64.b64encode(v).decode("ascii")

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def log_audit(msg: str):
    with open(AUDIT_FILENAME, "a", encoding="utf-8") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {msg}\n")

# -----------------------
# Vault helpers
# -----------------------
def vault_exists() -> bool:
    return os.path.exists(VAULT_FILENAME)

def create_vault_file(salt: bytes):
    data = {"salt": b64(salt), "entries": []}
    # totp will be added after encryption of secret
    with open(VAULT_FILENAME, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def load_vault():
    with open(VAULT_FILENAME, "r", encoding="utf-8") as f:
        return json.load(f)

def save_vault(data):
    with open(VAULT_FILENAME, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

# -----------------------
# Crypto primitives
# -----------------------
def derive_key(master_password: str, salt: bytes) -> bytes:
    pwd_bytes = master_password.encode("utf-8")
    key = hash_secret_raw(
        secret=pwd_bytes,
        salt=salt,
        time_cost=KDF_TIME_COST,
        memory_cost=KDF_MEMORY_COST,
        parallelism=KDF_PARALLELISM,
        hash_len=KDF_HASH_LEN,
        type=Type.ID
    )
    return key

def encrypt_bytes(key: bytes, plaintext: bytes) -> (bytes, bytes):
    aead = ChaCha20Poly1305(key)
    nonce = secrets.token_bytes(AEAD_NONCE_SIZE)
    ct = aead.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ct

def decrypt_bytes(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aead = ChaCha20Poly1305(key)
    pt = aead.decrypt(nonce, ciphertext, associated_data=None)
    return pt

# -----------------------
# Master password policy
# -----------------------
def check_master_password_policy(pw: str) -> (bool, str):
    """Return (ok, message)."""
    if len(pw) < MIN_LENGTH:
        return False, f"Password must be at least {MIN_LENGTH} characters long."
    if not re.search(r"[A-Z]", pw):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", pw):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", pw):
        return False, "Password must contain at least one digit."
    # special char check
    if not re.search(rf"[{re.escape(SPECIAL_CHARS)}]", pw):
        return False, "Password must contain at least one special character."
    return True, "OK"

# -----------------------
# Password Manager
# -----------------------
class PasswordManager:
    def __init__(self):
        self.unlocked = False
        self.key = None
        self.vault = None
        self.totp_secret = None  # plaintext totp secret after decrypting on unlock

    def init_vault(self, master_password: str):
        """Initialize vault: create salt, sentinel, and encrypted totp secret (and show QR)."""
        # enforce policy
        ok, msg = check_master_password_policy(master_password)
        if not ok:
            raise RuntimeError(msg)

        # prepare vault file
        salt = secrets.token_bytes(SALT_BYTES)
        create_vault_file(salt)
        key = derive_key(master_password, salt)

        # sentinel
        sentinel_plain = json.dumps({"test": "vault-ok"}).encode("utf-8")
        s_nonce, s_ct = encrypt_bytes(key, sentinel_plain)

        data = load_vault()
        data.setdefault("entries", [])
        data["entries"].append({
            "site": SENTINEL_SITE,
            "user": "_sentinel_",
            "nonce": b64(s_nonce),
            "ciphertext": b64(s_ct)
        })

        # generate TOTP secret and encrypt it into vault top-level field
        totp_secret_bytes = pyotp.random_base32().encode("utf-8")  # base32 bytes
        t_nonce, t_ct = encrypt_bytes(key, totp_secret_bytes)
        data[TOTP_FIELD] = {"nonce": b64(t_nonce), "ciphertext": b64(t_ct)}

        save_vault(data)

        # set unlocked and keep totp secret in memory for displaying QR to user
        self.key = key
        self.unlocked = True
        self.vault = data
        self.totp_secret = totp_secret_bytes.decode("utf-8")
        log_audit("Vault initialized (sentinel + totp created)")

    def unlock_vault(self, master_password: str):
        """Unlock vault: verify sentinel decryption and then require TOTP code verification."""
        if not vault_exists():
            raise RuntimeError("Vault does not exist.")
        data = load_vault()
        salt = ub64(data["salt"])
        key = derive_key(master_password, salt)

        # verify sentinel exists and decrypt
        sentinel = None
        for e in data.get("entries", []):
            if e.get("site") == SENTINEL_SITE:
                sentinel = e
                break
        if sentinel is None:
            log_audit("Failed unlock attempt: no sentinel present")
            raise RuntimeError("Vault missing sentinel entry - cannot verify password.")

        try:
            s_nonce = ub64(sentinel["nonce"])
            s_ct = ub64(sentinel["ciphertext"])
            pt = decrypt_bytes(key, s_nonce, s_ct)
            j = json.loads(pt.decode("utf-8"))
            if j.get("test") != "vault-ok":
                raise RuntimeError("Sentinel verification failed.")
        except Exception:
            log_audit("Failed unlock attempt (incorrect master password)")
            raise RuntimeError("Incorrect master password.")

        # decrypt TOTP secret
        if TOTP_FIELD not in data:
            log_audit("Failed unlock attempt: totp field missing")
            raise RuntimeError("Vault missing TOTP configuration.")
        try:
            t_nonce = ub64(data[TOTP_FIELD]["nonce"])
            t_ct = ub64(data[TOTP_FIELD]["ciphertext"])
            t_plain = decrypt_bytes(key, t_nonce, t_ct)
            totp_secret = t_plain.decode("utf-8")
        except Exception:
            log_audit("Failed unlock attempt: cannot decrypt totp (wrong key?)")
            raise RuntimeError("Failed to decrypt TOTP secret (incorrect master password).")

        self.key = key
        self.vault = data
        self.totp_secret = totp_secret

        log_audit("Master password verified; awaiting TOTP verification")

    def verify_totp_and_finalize_unlock(self, code: str) -> bool:
        """Verify provided TOTP code. Returns True if OK (and sets unlocked True)."""
        if self.totp_secret is None or self.key is None or self.vault is None:
            return False
        totp = pyotp.TOTP(self.totp_secret)
        ok = totp.verify(code.strip(), valid_window=1)  # allow ±30s window
        if ok:
            self.unlocked = True
            log_audit("Vault unlocked (TOTP success)")
            return True
        else:
            log_audit("Failed unlock attempt (invalid TOTP)")
            # clear in-memory sensitive state if TOTP fails
            self.key = None
            self.vault = None
            self.totp_secret = None
            return False

    def lock(self):
        self.unlocked = False
        self.key = None
        self.vault = None
        self.totp_secret = None
        log_audit("Vault locked")

    # Entry operations (standard)
    def add_entry(self, site: str, username: str, password: str):
        if not self.unlocked:
            raise RuntimeError("Vault locked.")
        plaintext = json.dumps({"user": username, "password": password}).encode("utf-8")
        nonce, ct = encrypt_bytes(self.key, plaintext)
        entry = {
            "site": site,
            "user": username,
            "nonce": b64(nonce),
            "ciphertext": b64(ct)
        }
        self.vault.setdefault("entries", []).append(entry)
        save_vault(self.vault)
        log_audit(f"ADD entry site={site} user={username}")

    def list_sites(self):
        if not self.unlocked:
            raise RuntimeError("Vault locked.")
        return sorted({e["site"] for e in self.vault.get("entries", []) if e.get("site") != SENTINEL_SITE})

    def get_entry(self, site: str):
        if not self.unlocked:
            raise RuntimeError("Vault locked.")
        for e in reversed(self.vault.get("entries", [])):
            if e["site"] == site:
                nonce = ub64(e["nonce"])
                ct = ub64(e["ciphertext"])
                pt = decrypt_bytes(self.key, nonce, ct)
                data = json.loads(pt.decode("utf-8"))
                log_audit(f"GET entry site={site} user={data.get('user')}")
                return data
        raise KeyError("No entry for site")

    def delete_entry(self, site: str):
        if not self.unlocked:
            raise RuntimeError("Vault locked.")
        before = len(self.vault.get("entries", []))
        new_entries = [e for e in self.vault.get("entries", []) if e["site"] != site]
        if before == len(new_entries):
            raise KeyError("No entry for site")
        self.vault["entries"] = new_entries
        save_vault(self.vault)
        log_audit(f"DELETE entries site={site}")

    # utility: return provisioning URI and secret for QR
    def get_totp_provisioning_uri(self, account_name: str = "user", issuer_name: str = "TkManager"):
        if not self.totp_secret:
            raise RuntimeError("TOTP secret not available.")
        totp = pyotp.TOTP(self.totp_secret)
        return totp.provisioning_uri(name=account_name, issuer_name=issuer_name), self.totp_secret

# -----------------------
# GUI
# -----------------------
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Vault")
        self.pm = PasswordManager()
        self.setup_widgets()

    def setup_widgets(self):
        frm = ttk.Frame(self.root, padding=12)
        frm.grid(sticky="nsew")

        # Top
        top = ttk.Frame(frm)
        top.grid(row=0, column=0, sticky="ew")
        self.status_var = tk.StringVar(value="Vault: (not initialized)")
        ttk.Label(top, textvariable=self.status_var).grid(row=0, column=0, sticky="w")

        btn_frame = ttk.Frame(top)
        btn_frame.grid(row=0, column=1, sticky="e")
        ttk.Button(btn_frame, text="Init Vault", command=self.cmd_init_vault).grid(row=0, column=0, padx=4)
        ttk.Button(btn_frame, text="Unlock", command=self.cmd_unlock).grid(row=0, column=1, padx=4)
        ttk.Button(btn_frame, text="Lock", command=self.cmd_lock).grid(row=0, column=2, padx=4)
        ttk.Button(btn_frame, text="Audit Log", command=self.show_audit).grid(row=0, column=3, padx=4)

        # Middle operations
        mid = ttk.LabelFrame(frm, text="Operations", padding=8)
        mid.grid(row=1, column=0, sticky="ew", pady=8)

        ttk.Label(mid, text="Site").grid(row=0, column=0, sticky="w")
        self.site_entry = ttk.Entry(mid, width=30)
        self.site_entry.grid(row=0, column=1, sticky="w", padx=4)

        ttk.Label(mid, text="Username").grid(row=1, column=0, sticky="w")
        self.user_entry = ttk.Entry(mid, width=30)
        self.user_entry.grid(row=1, column=1, sticky="w", padx=4)

        ttk.Label(mid, text="Password").grid(row=2, column=0, sticky="w")
        self.pw_entry = ttk.Entry(mid, width=30)
        self.pw_entry.grid(row=2, column=1, sticky="w", padx=4)

        gen_btn = ttk.Button(mid, text="Generate", command=self.cmd_generate_password)
        gen_btn.grid(row=2, column=2, padx=6)

        ttk.Button(mid, text="Add / Update", command=self.cmd_add_entry).grid(row=3, column=1, pady=6, sticky="w")

        ttk.Label(mid, text="Lookup Site").grid(row=4, column=0, sticky="w", pady=(8,0))
        self.lookup_entry = ttk.Entry(mid, width=30)
        self.lookup_entry.grid(row=4, column=1, sticky="w", padx=4, pady=(8,0))
        ttk.Button(mid, text="Get", command=self.cmd_get_entry).grid(row=4, column=2, padx=4, pady=(8,0))
        ttk.Button(mid, text="Delete", command=self.cmd_delete_entry).grid(row=4, column=3, padx=4, pady=(8,0))

        ttk.Button(mid, text="List Sites", command=self.cmd_list_sites).grid(row=5, column=1, pady=(6,0), sticky="w")

        out = ttk.LabelFrame(frm, text="Output", padding=8)
        out.grid(row=2, column=0, sticky="nsew")
        self.output = ScrolledText(out, width=70, height=14, state="disabled", wrap="word")
        self.output.grid(row=0, column=0)

        # layout weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        frm.columnconfigure(0, weight=1)
        out.columnconfigure(0, weight=1)

        self.update_status()

    def update_status(self):
        if not vault_exists():
            self.status_var.set("Vault: (not initialized)")
        elif self.pm.unlocked:
            self.status_var.set("Vault: (unlocked)")
        else:
            self.status_var.set("Vault: (exists, locked)")

    def append_output(self, text: str):
        self.output.configure(state="normal")
        self.output.insert("end", text + "\n")
        self.output.see("end")
        self.output.configure(state="disabled")

    def clear_ui_after_lock(self):
        for w in (self.site_entry, self.user_entry, self.pw_entry, self.lookup_entry):
            w.delete(0, tk.END)
        self.output.configure(state="normal")
        self.output.delete("1.0", tk.END)
        self.output.configure(state="disabled")

    # -----------------------
    # Command handlers
    # -----------------------
    def cmd_init_vault(self):
        if vault_exists():
            if not messagebox.askyesno("Init Vault", "Vault already exists. Overwrite?"):
                return
            # optional delete audit log
            if os.path.exists(AUDIT_FILENAME):
                if messagebox.askyesno("Init Vault", "Remove existing audit log as well? (Yes = remove)"):
                    try:
                        os.remove(AUDIT_FILENAME)
                    except Exception:
                        pass
            try:
                os.remove(VAULT_FILENAME)
            except Exception as e:
                messagebox.showerror("Error", f"Cannot remove existing vault file: {e}")
                return

        # ask for master password (enforce policy)
        while True:
            pw = simpledialog.askstring("Master Password", f"Enter new master password (min {MIN_LENGTH} chars):", show="*")
            if pw is None:
                return
            ok, msg = check_master_password_policy(pw)
            if ok:
                break
            else:
                messagebox.showwarning("Weak Password", msg)

        try:
            self.pm.init_vault(pw)
        except Exception as e:
            messagebox.showerror("Error initializing vault", str(e))
            return

        # Show QR to user for TOTP setup
        try:
            uri, secret = self.pm.get_totp_provisioning_uri(account_name="master", issuer_name="TkManager")
            self.show_qr_dialog(uri, secret)
        except Exception as e:
            messagebox.showwarning("TOTP Notice", f"TOTP provisioning failed to display: {e}")

        self.append_output("Vault initialized and unlocked. TOTP secret created.")
        messagebox.showinfo("Success", "Vault initialized. Scan the QR code with your Authenticator app.")
        self.update_status()

    def cmd_unlock(self):
        if not vault_exists():
            messagebox.showwarning("No Vault", "No vault found. Initialize first.")
            return
        pw = simpledialog.askstring("Master Password", "Enter master password:", show="*")
        if pw is None:
            return
        try:
            # this derives key and verifies sentinel, then decrypts totp secret, but does not finalize unlock
            self.pm.unlock_vault(pw)
        except Exception as e:
            messagebox.showerror("Error unlocking vault", str(e))
            return

        # prompt TOTP code
        code = simpledialog.askstring("2FA Code", "Enter 6-digit TOTP code from your Authenticator app:")
        if code is None:
            # clear in-memory sensitive things
            self.pm.key = None
            self.pm.vault = None
            self.pm.totp_secret = None
            messagebox.showinfo("Cancelled", "TOTP entry cancelled; vault remains locked.")
            return
        if self.pm.verify_totp_and_finalize_unlock(code):
            self.append_output("Vault unlocked (password + TOTP).")
            messagebox.showinfo("Unlocked", "Vault unlocked successfully.")
            self.update_status()
        else:
            messagebox.showerror("TOTP Failed", "Invalid TOTP code. Vault remains locked.")
            self.update_status()

    def cmd_lock(self):
        self.pm.lock()
        self.append_output("Vault locked.")
        self.clear_ui_after_lock()
        self.update_status()

    def cmd_generate_password(self):
        length = simpledialog.askinteger("Generate Password", "Length (8-64):", initialvalue=16, minvalue=8, maxvalue=64)
        if not length:
            return
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>?"
        pw = ''.join(secrets.choice(alphabet) for _ in range(length))
        self.pw_entry.delete(0, tk.END)
        self.pw_entry.insert(0, pw)
        self.append_output("Generated password (copied to password field).")

    def cmd_add_entry(self):
        site = self.site_entry.get().strip()
        user = self.user_entry.get().strip()
        pw = self.pw_entry.get().strip()
        if not (site and user and pw):
            messagebox.showwarning("Missing fields", "Provide site, username, and password.")
            return
        try:
            self.pm.add_entry(site, user, pw)
            self.append_output(f"Added entry for site: {site}")
            messagebox.showinfo("Added", f"Entry for {site} added.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def cmd_list_sites(self):
        try:
            sites = self.pm.list_sites()
            if not sites:
                self.append_output("No sites stored.")
            else:
                self.append_output("Sites:")
                for s in sites:
                    self.append_output("  - " + s)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def cmd_get_entry(self):
        site = self.lookup_entry.get().strip()
        if not site:
            messagebox.showwarning("Missing", "Enter site to lookup.")
            return
        try:
            data = self.pm.get_entry(site)
            self.append_output(f"Site: {site}\n  User: {data['user']}\n  Password: {data['password']}")
            if messagebox.askyesno("Copy", "Copy password to clipboard?"):
                self.root.clipboard_clear()
                self.root.clipboard_append(data['password'])
                self.append_output("Password copied to clipboard.")
        except KeyError:
            messagebox.showinfo("Not found", f"No entry for {site}.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def cmd_delete_entry(self):
        site = self.lookup_entry.get().strip()
        if not site:
            messagebox.showwarning("Missing", "Enter site to delete.")
            return
        if not messagebox.askyesno("Confirm Delete", f"Delete all entries for {site}?"):
            return
        try:
            self.pm.delete_entry(site)
            self.append_output(f"Deleted entries for site: {site}")
            messagebox.showinfo("Deleted", f"Entries for {site} deleted.")
        except KeyError:
            messagebox.showinfo("Not found", f"No entry for {site}.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def show_audit(self):
        # Only allow viewing audit file when unlocked
        if not self.pm.unlocked:
            messagebox.showwarning("Locked", "Unlock the vault to view the audit log.")
            return
        if not os.path.exists(AUDIT_FILENAME):
            messagebox.showinfo("Audit Log", "No audit log found.")
            return
        with open(AUDIT_FILENAME, "r", encoding="utf-8") as f:
            text = f.read()
        dlg = tk.Toplevel(self.root)
        dlg.title("Audit Log")
        txt = ScrolledText(dlg, width=80, height=30)
        txt.insert("1.0", text)
        txt.configure(state="disabled")
        txt.pack(padx=6, pady=6)

    # QR dialog for provisioning
    def show_qr_dialog(self, provisioning_uri: str, secret: str):
        # Create QR code image with qrcode + PIL, then show in Toplevel
        qr = qrcode.QRCode(border=2)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white").convert("RGB")

        dlg = tk.Toplevel(self.root)
        dlg.title("TOTP Setup - Scan QR")
        # show image
        imgtk = ImageTk.PhotoImage(img)
        lbl = ttk.Label(dlg, image=imgtk)
        lbl.image = imgtk  # keep reference
        lbl.pack(padx=8, pady=8)
        ttk.Label(dlg, text=f"Secret (base32): {secret}").pack(padx=8, pady=(0,8))
        ttk.Button(dlg, text="OK", command=dlg.destroy).pack(pady=(0,8))

# -----------------------
# Run App
# -----------------------
def main():
    root = tk.Tk()
    app = App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
