import hashlib
import tkinter as tk
from tkinter import ttk

def sha256(text):
    encoded_text = text.encode('utf-8')
    sha256_hash = hashlib.sha256(encoded_text)
    hex_digest = sha256_hash.hexdigest()
    return hex_digest

def handle_input_change(*args):
  input_text = input_var.get()
  output_text.config(state=tk.NORMAL)
  output_text.delete("1.0", tk.END)

  if input_text:
    hashed_output = sha256(input_text)
    output_text.insert(tk.END, hashed_output)
  else:
    output_text.insert(tk.END, "")

  output_text.config(state=tk.DISABLED)

def copy_output_to_clipboard(event=None):
    output_text.config(state=tk.NORMAL)
    output_content = output_text.get("1.0", tk.END).strip()
    output_text.config(state=tk.DISABLED)

    if output_content:
        window.clipboard_clear()
        window.clipboard_append(output_content)

window = tk.Tk()
window.title("sha256 converter")
window.geometry("150x150")
window.resizable(False, False)
window.config(background="#2b2a33")

style = ttk.Style()
style.theme_use('clam')
style.configure("TEntry", 
                fieldbackground="#42414d", 
                foreground="#ffffff", 
                background="#42414d", 
                highlightthickness=0, 
                relief="flat", 
                bordercolor="#42414d")

style.map("TEntry",
          borderwidth=[('focus', 2)],
          relief=[('focus', 'solid')],
          bordercolor=[('focus', '#00ffff')],
          lightcolor=[('focus', '#00ffff')]
         )

input_label = ttk.Label(window, text="Input")
input_label.config(background="#2b2a33", 
                   foreground="#ffffff")
input_label.pack()

input_var = tk.StringVar()
input_var.trace_add("write", handle_input_change)

input_entry = ttk.Entry(window, textvariable=input_var)
input_entry.pack(fill=tk.X)

output_label = ttk.Label(window, text="Output")
output_label.config(background="#2b2a33", foreground="#ffffff")
output_label.pack()

output_text = tk.Text(window, 
                      wrap=tk.WORD, 
                      relief=tk.SOLID, 
                      highlightthickness=0, 
                      border=0, 
                      background=window.cget("bg"),
                      cursor="arrow")
output_text.pack(fill=tk.X)
output_text.config(state=tk.DISABLED, foreground="#ffffff")
output_text.bind("<Button-1>", copy_output_to_clipboard)

input_entry.focus()

window.mainloop()