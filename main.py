import tkinter as tk
from datetime import datetime
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk
from pymongo import MongoClient
import string
import random

# MongoDB'ye bağlan
client = MongoClient('mongodb://localhost:27017/')
db = client['sbg_sifreleme_uyg']

# Kullanıcı ve geçmiş koleksiyonlarını seç
users_collection = db['users']
history_collection = db['history']

current_user = None

# Kontrol fonksiyonu
def check_login():
    global current_user
    if current_user:
        enable_encryption_ui()
        notebook.select(encryption_tab)
    else:
        disable_encryption_ui()
        notebook.select(login_tab)

# Bu fonksiyon her sekmeye tıklamadan önce çağrılır
def on_tab_change(event):
    if current_user:  # Kullanıcı giriş yaptıysa
        check_login()
    else:
        messagebox.showwarning("Uyarı", "Lütfen önce giriş yapın.")
        notebook.select(login_tab)


def login():
    global current_user
    username = username_entry.get()
    password = password_entry.get()
    # MongoDB'den kullanıcıyı kontrol et
    user = users_collection.find_one({'username': username, 'password': password})

    if user:
        current_user = username
        # Giriş yapıldığında mesajı göster
        messagebox.showinfo("Giriş Başarılı", f"Hoş geldiniz, {current_user}!")
    else:
        current_user = None
        # Giriş başarısız olduğunda hata mesajını göster
        messagebox.showwarning("Hatalı Giriş", "Hatalı kullanıcı adı veya şifre. Lütfen tekrar deneyin.")
        login_status_label.config(text="")

    # Kontrol fonksiyonunu çağır
    check_login()
    if user:
        current_user = username
        enable_encryption_ui()
        # Giriş yapıldığında mesajı göster
        messagebox.showinfo("Giriş Başarılı", f"Hoş geldiniz, {current_user}!")
    else:
        current_user = None
        login_status_label.config(text="Hatalı kullanıcı adı veya şifre")

def register():
    username = username_entry.get()
    password = password_entry.get()

    # MongoDB'ye yeni kullanıcı ekle
    if username and password:
        users_collection.insert_one({'username': username, 'password': password})
        messagebox.showinfo("Kayıt Başarılı", "Kullanıcı kaydı başarıyla oluşturuldu.")
    else:
        messagebox.showerror("Hata", "Kullanıcı adı ve şifre alanları boş bırakılamaz.")

def enable_encryption_ui():
    encryption_tab.state(["!disabled"])
    notebook.select(encryption_tab)
    cipher_type_menu.bind("<<ComboboxSelected>>", select_cipher_type)

def add_to_history(action, details):
    history_collection.insert_one({'action': action, 'details': details, 'timestamp': datetime.now()})

def show_history():
    history_text = "Geçmiş İşlemler:\n\n"
    # MongoDB'den geçmiş verileri al
    history_entries = history_collection.find()
    for entry in history_entries:
        history_text += f"{entry['action']}: {entry['details']} ({entry['timestamp']})\n"

    messagebox.showinfo("Geçmiş İşlemler", history_text)
    check_login()

def disable_encryption_ui():
    encryption_tab.state(["disabled"])
    notebook.select(login_tab)
    input_text.delete("1.0", "end")
    output_text.delete("1.0", "end")
    cipher_type_menu.set("Sezar")
    shift_entry.delete(0, "end")
    xor_key_entry.delete(0, "end")

def caesar_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            offset = ord('a') if char.islower() else ord('A')
            result += chr((ord(char) - offset + shift) % 26 + offset)
        else:
            result += char
    return result

def xor_cipher(text, key):
    result = ""
    key_length = len(key)
    for i in range(len(text)):
        result += chr(ord(text[i]) ^ ord(key[i % key_length]))
    return result

def reverse_cipher(text):
    return text[::-1]

def save_encrypted_message():
    encrypted_message = output_text.get("1.0", "end-1c")
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, "w") as file:
            file.write(encrypted_message)
        messagebox.showinfo("Dosya Kaydedildi", f"Şifrelenmiş metin dosyası kaydedildi: {file_path}")

def open_text_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, "r") as file:
            text = file.read()
            input_text.delete("1.0", "end")
            input_text.insert("1.0", text)
        messagebox.showinfo("Dosya Açıldı", f"Metin dosyası açıldı: {file_path}")

def copy_to_clipboard():
    encrypted_message = output_text.get("1.0", "end-1c")
    window.clipboard_clear()
    window.clipboard_append(encrypted_message)
    window.update()
    messagebox.showinfo("Panoya Kopyalandı", "Şifrelenmiş metin panoya kopyalandı.")

def decrypt_message():
    message = output_text.get("1.0", "end-1c")
    cipher_type = cipher_type_var.get()

    if cipher_type == "Sezar":
        shift_entry_value = shift_entry.get()
        if not shift_entry_value:
            messagebox.showerror("Hata", "Kaydırma miktarı boş bırakılamaz.")
            return

        shift = int(shift_entry_value)
        decrypted_message = caesar_cipher(message, -shift)
        info_message = "Mesaj Sezar şifrelemesi ile çözüldü."
    elif cipher_type == "XOR":
        xor_key_entry_value = xor_key_entry.get()
        if not xor_key_entry_value:
            messagebox.showerror("Hata", "XOR anahtarı boş bırakılamaz.")
            return

        decrypted_message = xor_cipher(message, xor_key_entry_value)
        info_message = "Mesaj XOR şifrelemesi ile çözüldü."
    else:

        info_message = "Geçerli bir şifreleme yöntemi seçilmedi."

    input_text.delete("1.0", "end")
    input_text.insert("1.0", decrypted_message)
    add_to_history("Decrypt", f"{info_message} ({datetime.now()})")
    messagebox.showinfo("Çözme İşlemi", info_message)


def clear_input_fields():
    shift_entry.delete(0, "end")
    xor_key_entry.delete(0, "end")

def encrypt_message():
    message = input_text.get("1.0", "end-1c")
    cipher_type = cipher_type_var.get()

    if cipher_type == "Sezar":
        shift_entry_value = shift_entry.get()
        if not shift_entry_value:
            messagebox.showerror("Hata", "Kaydırma miktarı boş bırakılamaz.")
            return

        shift = int(shift_entry_value)
        encrypted_message = caesar_cipher(message, shift)
        info_message = "Mesaj Sezar şifrelemesi ile şifrelendi."
    elif cipher_type == "XOR":
        xor_key_entry_value = xor_key_entry.get()
        if not xor_key_entry_value:
            messagebox.showerror("Hata", "XOR anahtarı boş bırakılamaz.")
            return

        encrypted_message = xor_cipher(message, xor_key_entry_value)
        info_message = "Mesaj XOR şifrelemesi ile şifrelendi."

    elif cipher_type == "Reverse":
        encrypted_message = reverse_cipher(message)
        info_message = "Mesaj ters çevirme şifrelemesi ile şifrelendi."
    else:
        info_message = "Geçerli bir şifreleme yöntemi seçilmedi."


    output_text.delete("1.0", "end")
    output_text.insert("1.0", encrypted_message)
    add_to_history("Encrypt", f"{info_message} ({datetime.now()})")
    messagebox.showinfo("Şifreleme Türü", info_message)


def select_cipher_type(event):
    selected_cipher = cipher_type_var.get()
    if selected_cipher in ["Sezar", "XOR", "Reverse"]:
        change_background(f"{selected_cipher.lower()}.jpeg")
    else:
        change_background("background.jpeg")

def change_background(image_path):
    global background_photo
    background_image = Image.open(image_path)
    background_image = background_image.resize((1920, 1080), Image.ANTIALIAS)
    background_photo = ImageTk.PhotoImage(background_image)
    canvas.delete("all")  # Önceki resmi temizle
    canvas.create_image(0, 0, image=background_photo, anchor=tk.NW)
    window.update()


# Yeni işlemi geçmişe ekle
def add_to_history(action, details):
    history_collection.insert_one({'action': action, 'details': details, 'timestamp': datetime.now()})


# Geçmiş penceresini göster
def show_history():
    history_text = "Geçmiş İşlemler:\n\n"

    # MongoDB'den geçmiş verileri al
    history_entries = history_collection.find()

    for entry in history_entries:
        history_text += f"{entry['action']}: {entry['details']} ({entry['timestamp']})\n"

    messagebox.showinfo("Geçmiş İşlemler", history_text)


def generate_password_strength(strength):
    if strength == 1:
        # Seviye 1 için: Kolay ve kısa şifre
        length = 6
        characters = string.ascii_lowercase + string.digits
    elif strength == 2:
        # Seviye 2 için: Biraz daha zorlu ve birkaç karakter daha uzun şifre
        length = 8
        characters = string.ascii_letters + string.digits
    elif strength == 3:
        # Seviye 3 için: Orta düzeyde zorlukta şifre
        length = 10
        characters = string.ascii_letters + string.digits + string.punctuation
    elif strength == 4:
        # Seviye 4 için: Güçlü şifre
        length = 12
        characters = string.ascii_letters + string.digits + string.punctuation
    elif strength == 5:
        # Seviye 5 için: Çok güçlü şifre
        length = 16
        characters = string.ascii_letters + string.digits + string.punctuation

    generated_password = ''.join(random.choice(characters) for _ in range(length))
    return generated_password

def copy_generated_password():
    try:
        strength = int(strength_var.get())
        if strength < 1 or strength > 5:
            raise ValueError()

        strong_password = generate_password_strength(strength)
        password_text.delete("1.0", "end")
        password_text.insert("1.0", strong_password)

        # Calculate password strength and display stars
        strength_label.config(text="Şifre Gücü: " + "★" * strength + "☆" * (5 - strength))

        window.clipboard_clear()
        window.clipboard_append(strong_password)
        window.update()
        messagebox.showinfo("Şifre Önerisi", f"Güçlü şifre önerisi: {strong_password} (Panoya kopyalandı)")

    except ValueError:
        messagebox.showerror("Hata", "Lütfen geçerli bir şifre gücü belirtin (1 ile 5 arasında bir tam sayı).")



window = tk.Tk()
window.title("Şifreleme Uygulaması")
window.geometry("1920x1080")

# Pencere boyutunu ve konumunu ayarlayın
window_width = 800
window_height = 600

# Pencereyi ekranın üstünden 10 piksel daha aşağıda yerleştirin
x_coordinate = (window.winfo_screenwidth() - window_width) // 2
y_coordinate = 10  # 10 piksel aşağıda

# Pencereyi yerleştirin
window.geometry(f"{window_width}x{window_height}+{x_coordinate}+{y_coordinate}")

canvas = tk.Canvas(window, bd=0, highlightthickness=0)
canvas.pack(fill="both", expand=True)

background_image = Image.open("background.jpeg")
background_image = background_image.resize((1920, 1080), Image.ANTIALIAS)
background_photo = ImageTk.PhotoImage(background_image)
canvas.create_image(0, 0, image=background_photo, anchor=tk.NW)

background_image.putalpha(128)

style = ttk.Style()
style.configure("TButton", padding=6, relief="flat", font=("Helvetica", 12))
style.map("TButton", background=[("active", "#ff5733")])
style.map("TButton", foreground=[("pressed", "#ffffff")])

notebook = ttk.Notebook(canvas)
notebook.pack()
login_tab = ttk.Frame(notebook)
notebook.add(login_tab, text="Giriş")

username_label = ttk.Label(login_tab, text="Kullanıcı Adı:")
username_label.pack(pady=5)
username_entry = ttk.Entry(login_tab)
username_entry.pack()

password_label = ttk.Label(login_tab, text="Şifre:")
password_label.pack(pady=5)
password_entry = ttk.Entry(login_tab, show="*")
password_entry.pack()

login_button = ttk.Button(login_tab, text="Giriş Yap", command=login)
login_button.pack(pady=10)

register_button = ttk.Button(login_tab, text="Kayıt Ol", command=register)
register_button.pack(pady=10)

login_status_label = ttk.Label(login_tab, text="")
login_status_label.pack(pady=5)

encryption_tab = ttk.Frame(notebook)
notebook.add(encryption_tab, text="Şifreleme")

input_label = ttk.Label(encryption_tab, text="Şifrelenecek Mesaj:")
input_label.pack(pady=5)
input_text = tk.Text(encryption_tab, height=5, width=40)
input_text.pack()

cipher_type_var = tk.StringVar(value="Sezar")
cipher_type_label = ttk.Label(encryption_tab, text="Şifreleme Türü:")
cipher_type_label.pack(pady=5)
cipher_type_menu = ttk.Combobox(encryption_tab, textvariable=cipher_type_var, values=["Sezar", "XOR","Reverse"])
cipher_type_menu.pack()

shift_label = ttk.Label(encryption_tab, text="Kaydırma Miktarı (Sezar için):")
shift_label.pack(pady=5)
shift_entry = ttk.Entry(encryption_tab)
shift_entry.pack()

xor_key_label = ttk.Label(encryption_tab, text="XOR Anahtarı (XOR için):")
xor_key_label.pack(pady=5)
xor_key_entry = ttk.Entry(encryption_tab)
xor_key_entry.pack()

encrypt_button = ttk.Button(encryption_tab, text="Şifrele", command=encrypt_message)
encrypt_button.pack(pady=10)
decrypt_button = ttk.Button(encryption_tab, text="Çöz", command=decrypt_message)
decrypt_button.pack()

output_text = tk.Text(encryption_tab, height=5, width=40)
output_text.pack()

file_tab = ttk.Frame(notebook)
notebook.add(file_tab, text="Dosya İşleme")

save_button = ttk.Button(file_tab, text="Şifrelenmiş Metni Kaydet", command=save_encrypted_message)
save_button.pack(pady=10)
open_button = ttk.Button(file_tab, text="Metin Dosyası Aç", command=open_text_file)
open_button.pack()

copy_button = ttk.Button(encryption_tab, text="Panoya Kopyala", command=copy_to_clipboard)
copy_button.pack(pady=10)
clear_button = ttk.Button(encryption_tab, text="Temizle", command=clear_input_fields)
clear_button.pack()

history_button = ttk.Button(encryption_tab, text="Geçmişi Göster", command=show_history)
history_button.pack(pady=10)

password_suggestion_tab = ttk.Frame(notebook)
notebook.add(password_suggestion_tab, text="Şifre Önerisi")

# Güç seviyesini seçmek için bir Combobox ekleyin
strength_var = tk.StringVar(value="3")  # Varsayılan güç seviyesi
strength_label = ttk.Label(password_suggestion_tab, text="Şifre Gücü:")
strength_label.pack(pady=5)
strength_menu = ttk.Combobox(password_suggestion_tab, textvariable=strength_var, values=["1", "2", "3", "4", "5"])
strength_menu.pack(pady=5)

generate_password_button = ttk.Button(password_suggestion_tab, text="Şifre Önerisi Al", command=copy_generated_password)
generate_password_button.pack(pady=10)

password_text = tk.Text(password_suggestion_tab, height=1, width=40)
password_text.pack(pady=5)

strength_label = ttk.Label(password_suggestion_tab, text="Şifre Gücü: ☆☆☆☆☆")
strength_label.pack(pady=5)

copy_password_button = ttk.Button(password_suggestion_tab, text="Panoya Kopyala", command=copy_generated_password)
copy_password_button.pack(pady=10)

# Başlangıçta varsayılan arka plan resmini kullan
change_background("background.jpeg")

#if not current_user:
    #notebook.bind("<ButtonRelease-1>", on_tab_change)
window.mainloop()