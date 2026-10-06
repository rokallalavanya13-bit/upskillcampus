import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import secrets
import string
import base64
import hashlib
from cryptography.fernet import Fernet


# =========================================================
# DATABASE
# =========================================================

conn = sqlite3.connect("password_manager.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    master_password TEXT NOT NULL,
    encryption_key TEXT NOT NULL
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    website TEXT NOT NULL,
    account_username TEXT NOT NULL,
    encrypted_password TEXT NOT NULL
)
""")

conn.commit()


# =========================================================
# GLOBAL VARIABLES
# =========================================================

current_user = None
cipher = None


# =========================================================
# PASSWORD HASHING
# =========================================================

def hash_master_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# =========================================================
# ENCRYPTION KEY
# =========================================================

def create_encryption_key(master_password):
    """
    Creates a deterministic Fernet key from the master password.
    """

    digest = hashlib.sha256(
        master_password.encode()
    ).digest()

    return base64.urlsafe_b64encode(digest)


# =========================================================
# REGISTER USER
# =========================================================

def register_user():
    username = register_username_entry.get().strip()
    master_password = register_password_entry.get()
    confirm_password = register_confirm_entry.get()

    if username == "" or master_password == "":
        messagebox.showwarning(
            "Warning",
            "Please fill all fields."
        )
        return

    if master_password != confirm_password:
        messagebox.showerror(
            "Error",
            "Passwords do not match."
        )
        return

    if len(master_password) < 8:
        messagebox.showwarning(
            "Weak Password",
            "Master password must contain at least 8 characters."
        )
        return

    hashed_password = hash_master_password(
        master_password
    )

    encryption_key = create_encryption_key(
        master_password
    )

    try:

        cursor.execute("""
        INSERT INTO users
        (username, master_password, encryption_key)
        VALUES (?, ?, ?)
        """, (
            username,
            hashed_password,
            encryption_key.decode()
        ))

        conn.commit()

        messagebox.showinfo(
            "Success",
            "Account created successfully!"
        )

        register_username_entry.delete(0, tk.END)
        register_password_entry.delete(0, tk.END)
        register_confirm_entry.delete(0, tk.END)

        show_login()

    except sqlite3.IntegrityError:

        messagebox.showerror(
            "Error",
            "Username already exists."
        )


# =========================================================
# LOGIN
# =========================================================

def login_user():

    global current_user
    global cipher

    username = login_username_entry.get().strip()
    master_password = login_password_entry.get()

    if username == "" or master_password == "":
        messagebox.showwarning(
            "Warning",
            "Enter username and master password."
        )
        return

    hashed_password = hash_master_password(
        master_password
    )

    cursor.execute("""
    SELECT username, encryption_key
    FROM users
    WHERE username = ? AND master_password = ?
    """, (
        username,
        hashed_password
    ))

    result = cursor.fetchone()

    if result:

        current_user = username

        cipher = Fernet(
            result[1].encode()
        )

        login_username_entry.delete(
            0,
            tk.END
        )

        login_password_entry.delete(
            0,
            tk.END
        )

        show_dashboard()

    else:

        messagebox.showerror(
            "Login Failed",
            "Invalid username or master password."
        )


# =========================================================
# LOGOUT
# =========================================================

def logout():

    global current_user
    global cipher

    current_user = None
    cipher = None

    show_login()


# =========================================================
# ENCRYPT PASSWORD
# =========================================================

def encrypt_password(password):

    return cipher.encrypt(
        password.encode()
    ).decode()


# =========================================================
# DECRYPT PASSWORD
# =========================================================

def decrypt_password(encrypted_password):

    return cipher.decrypt(
        encrypted_password.encode()
    ).decode()


# =========================================================
# GENERATE PASSWORD
# =========================================================

def generate_password():

    characters = (
        string.ascii_letters
        + string.digits
        + "!@#$%^&*()-_=+"
    )

    password = "".join(
        secrets.choice(characters)
        for _ in range(16)
    )

    password_entry.delete(
        0,
        tk.END
    )

    password_entry.insert(
        0,
        password
    )


# =========================================================
# SHOW / HIDE PASSWORD
# =========================================================

def toggle_password():

    if password_entry.cget("show") == "*":

        password_entry.config(show="")

        show_hide_button.config(
            text="Hide"
        )

    else:

        password_entry.config(show="*")

        show_hide_button.config(
            text="Show"
        )


# =========================================================
# ADD PASSWORD
# =========================================================

def add_password():

    website = website_entry.get().strip()
    account_username = account_username_entry.get().strip()
    password = password_entry.get()

    if website == "":
        messagebox.showwarning(
            "Warning",
            "Enter website."
        )
        return

    if account_username == "":
        messagebox.showwarning(
            "Warning",
            "Enter account username."
        )
        return

    if password == "":
        messagebox.showwarning(
            "Warning",
            "Enter password."
        )
        return

    encrypted_password = encrypt_password(
        password
    )

    cursor.execute("""
    INSERT INTO passwords
    (username, website, account_username, encrypted_password)
    VALUES (?, ?, ?, ?)
    """, (
        current_user,
        website,
        account_username,
        encrypted_password
    ))

    conn.commit()

    messagebox.showinfo(
        "Success",
        "Password saved securely."
    )

    website_entry.delete(
        0,
        tk.END
    )

    account_username_entry.delete(
        0,
        tk.END
    )

    password_entry.delete(
        0,
        tk.END
    )

    load_passwords()


# =========================================================
# LOAD PASSWORDS
# =========================================================

def load_passwords():

    for item in password_tree.get_children():
        password_tree.delete(item)

    cursor.execute("""
    SELECT id, website, account_username
    FROM passwords
    WHERE username = ?
    ORDER BY website
    """, (current_user,))

    records = cursor.fetchall()

    for record in records:

        password_tree.insert(
            "",
            tk.END,
            values=(
                record[0],
                record[1],
                record[2],
                "********"
            )
        )


# =========================================================
# VIEW SELECTED PASSWORD
# =========================================================

def view_password():

    selected = password_tree.selection()

    if not selected:
        messagebox.showwarning(
            "Warning",
            "Select an account first."
        )
        return

    item = password_tree.item(
        selected[0]
    )

    password_id = item["values"][0]

    cursor.execute("""
    SELECT website,
           account_username,
           encrypted_password
    FROM passwords
    WHERE id = ? AND username = ?
    """, (
        password_id,
        current_user
    ))

    record = cursor.fetchone()

    if record:

        try:

            original_password = decrypt_password(
                record[2]
            )

            messagebox.showinfo(
                "Password Details",
                f"Website: {record[0]}\n\n"
                f"Username: {record[1]}\n\n"
                f"Password: {original_password}"
            )

        except Exception:

            messagebox.showerror(
                "Error",
                "Unable to decrypt password."
            )


# =========================================================
# SEARCH PASSWORDS
# =========================================================

def search_passwords():

    search_text = search_entry.get().strip()

    for item in password_tree.get_children():
        password_tree.delete(item)

    cursor.execute("""
    SELECT id, website, account_username
    FROM passwords
    WHERE username = ?
    AND (
        website LIKE ?
        OR account_username LIKE ?
    )
    ORDER BY website
    """, (
        current_user,
        "%" + search_text + "%",
        "%" + search_text + "%"
    ))

    records = cursor.fetchall()

    for record in records:

        password_tree.insert(
            "",
            tk.END,
            values=(
                record[0],
                record[1],
                record[2],
                "********"
            )
        )


# =========================================================
# DELETE PASSWORD
# =========================================================

def delete_password():

    selected = password_tree.selection()

    if not selected:
        messagebox.showwarning(
            "Warning",
            "Select an account to delete."
        )
        return

    item = password_tree.item(
        selected[0]
    )

    password_id = item["values"][0]

    confirm = messagebox.askyesno(
        "Confirm Delete",
        "Are you sure you want to delete this password?"
    )

    if not confirm:
        return

    cursor.execute("""
    DELETE FROM passwords
    WHERE id = ? AND username = ?
    """, (
        password_id,
        current_user
    ))

    conn.commit()

    messagebox.showinfo(
        "Deleted",
        "Password deleted successfully."
    )

    load_passwords()


# =========================================================
# CLEAR SEARCH
# =========================================================

def clear_search():

    search_entry.delete(
        0,
        tk.END
    )

    load_passwords()


# =========================================================
# CLEAR INPUTS
# =========================================================

def clear_inputs():

    website_entry.delete(
        0,
        tk.END
    )

    account_username_entry.delete(
        0,
        tk.END
    )

    password_entry.delete(
        0,
        tk.END
    )


# =========================================================
# CLEAR FRAME
# =========================================================

def clear_frame():

    for widget in root.winfo_children():
        widget.destroy()


# =========================================================
# LOGIN SCREEN
# =========================================================

def show_login():

    global login_username_entry
    global login_password_entry

    clear_frame()

    frame = tk.Frame(
        root,
        padx=30,
        pady=30
    )

    frame.pack(
        expand=True
    )

    tk.Label(
        frame,
        text="PASSWORD MANAGER",
        font=("Arial", 22, "bold")
    ).pack(pady=15)

    tk.Label(
        frame,
        text="Login",
        font=("Arial", 14)
    ).pack(pady=5)

    tk.Label(
        frame,
        text="Username"
    ).pack()

    login_username_entry = tk.Entry(
        frame,
        width=35
    )

    login_username_entry.pack(
        pady=5
    )

    tk.Label(
        frame,
        text="Master Password"
    ).pack()

    login_password_entry = tk.Entry(
        frame,
        width=35,
        show="*"
    )

    login_password_entry.pack(
        pady=5
    )

    tk.Button(
        frame,
        text="Login",
        width=25,
        command=login_user
    ).pack(pady=15)

    tk.Button(
        frame,
        text="Create New Account",
        width=25,
        command=show_register
    ).pack()

    tk.Label(
        frame,
        text="Your master password protects your stored credentials.",
        fg="gray"
    ).pack(pady=20)


# =========================================================
# REGISTER SCREEN
# =========================================================

def show_register():

    global register_username_entry
    global register_password_entry
    global register_confirm_entry

    clear_frame()

    frame = tk.Frame(
        root,
        padx=30,
        pady=20
    )

    frame.pack(
        expand=True
    )

    tk.Label(
        frame,
        text="CREATE ACCOUNT",
        font=("Arial", 20, "bold")
    ).pack(pady=15)

    tk.Label(
        frame,
        text="Username"
    ).pack()

    register_username_entry = tk.Entry(
        frame,
        width=35
    )

    register_username_entry.pack(
        pady=5
    )

    tk.Label(
        frame,
        text="Master Password"
    ).pack()

    register_password_entry = tk.Entry(
        frame,
        width=35,
        show="*"
    )

    register_password_entry.pack(
        pady=5
    )

    tk.Label(
        frame,
        text="Confirm Master Password"
    ).pack()

    register_confirm_entry = tk.Entry(
        frame,
        width=35,
        show="*"
    )

    register_confirm_entry.pack(
        pady=5
    )

    tk.Button(
        frame,
        text="Create Account",
        width=25,
        command=register_user
    ).pack(pady=15)

    tk.Button(
        frame,
        text="Back to Login",
        width=25,
        command=show_login
    ).pack()


# =========================================================
# DASHBOARD
# =========================================================

def show_dashboard():

    global website_entry
    global account_username_entry
    global password_entry
    global show_hide_button
    global search_entry
    global password_tree

    clear_frame()

    # ---------------- TOP ----------------

    top_frame = tk.Frame(
        root,
        padx=15,
        pady=10
    )

    top_frame.pack(
        fill="x"
    )

    tk.Label(
        top_frame,
        text=f"Welcome, {current_user}",
        font=("Arial", 16, "bold")
    ).pack(side="left")

    tk.Button(
        top_frame,
        text="Logout",
        command=logout
    ).pack(side="right")

    # ---------------- ADD FRAME ----------------

    add_frame = tk.LabelFrame(
        root,
        text="Add New Password",
        padx=15,
        pady=15
    )

    add_frame.pack(
        fill="x",
        padx=20,
        pady=10
    )

    tk.Label(
        add_frame,
        text="Website"
    ).grid(
        row=0,
        column=0,
        padx=5,
        pady=5
    )

    website_entry = tk.Entry(
        add_frame,
        width=30
    )

    website_entry.grid(
        row=0,
        column=1,
        padx=5,
        pady=5
    )

    tk.Label(
        add_frame,
        text="Username"
    ).grid(
        row=1,
        column=0,
        padx=5,
        pady=5
    )

    account_username_entry = tk.Entry(
        add_frame,
        width=30
    )

    account_username_entry.grid(
        row=1,
        column=1,
        padx=5,
        pady=5
    )

    tk.Label(
        add_frame,
        text="Password"
    ).grid(
        row=2,
        column=0,
        padx=5,
        pady=5
    )

    password_entry = tk.Entry(
        add_frame,
        width=30,
        show="*"
    )

    password_entry.grid(
        row=2,
        column=1,
        padx=5,
        pady=5
    )

    show_hide_button = tk.Button(
        add_frame,
        text="Show",
        command=toggle_password
    )

    show_hide_button.grid(
        row=2,
        column=2,
        padx=5
    )

    tk.Button(
        add_frame,
        text="Generate Password",
        command=generate_password
    ).grid(
        row=3,
        column=1,
        pady=10
    )

    tk.Button(
        add_frame,
        text="Save Password",
        command=add_password
    ).grid(
        row=4,
        column=1,
        pady=5
    )

    tk.Button(
        add_frame,
        text="Clear",
        command=clear_inputs
    ).grid(
        row=4,
        column=2,
        padx=5
    )

    # ---------------- SEARCH ----------------

    search_frame = tk.Frame(
        root,
        padx=20,
        pady=5
    )

    search_frame.pack(
        fill="x"
    )

    tk.Label(
        search_frame,
        text="Search:"
    ).pack(
        side="left"
    )

    search_entry = tk.Entry(
        search_frame,
        width=35
    )

    search_entry.pack(
        side="left",
        padx=5
    )

    tk.Button(
        search_frame,
        text="Search",
        command=search_passwords
    ).pack(
        side="left",
        padx=3
    )

    tk.Button(
        search_frame,
        text="Clear",
        command=clear_search
    ).pack(
        side="left",
        padx=3
    )

    # ---------------- TABLE ----------------

    table_frame = tk.Frame(
        root,
        padx=20,
        pady=10
    )

    table_frame.pack(
        fill="both",
        expand=True
    )

    columns = (
        "ID",
        "Website",
        "Username",
        "Password"
    )

    password_tree = ttk.Treeview(
        table_frame,
        columns=columns,
        show="headings"
    )

    for column in columns:

        password_tree.heading(
            column,
            text=column
        )

    password_tree.column(
        "ID",
        width=50
    )

    password_tree.column(
        "Website",
        width=150
    )

    password_tree.column(
        "Username",
        width=180
    )

    password_tree.column(
        "Password",
        width=120
    )

    password_tree.pack(
        fill="both",
        expand=True
    )

    # ---------------- ACTION BUTTONS ----------------

    action_frame = tk.Frame(
        root,
        pady=10
    )

    action_frame.pack()

    tk.Button(
        action_frame,
        text="View Password",
        command=view_password
    ).pack(
        side="left",
        padx=5
    )

    tk.Button(
        action_frame,
        text="Delete",
        command=delete_password
    ).pack(
        side="left",
        padx=5
    )

    load_passwords()


# =========================================================
# MAIN WINDOW
# =========================================================

root = tk.Tk()

root.title(
    "Password Manager"
)

root.geometry(
    "850x650"
)

root.minsize(
    750,
    550
)

root.protocol(
    "WM_DELETE_WINDOW",
    lambda: (
        conn.close(),
        root.destroy()
    )
)

show_login()

root.mainloop()