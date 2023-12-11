import pyperclip
import tkinter as tk
from tkinter import simpledialog, Label, Radiobutton, StringVar

# Function to perform the encryption/decryption
# SYMBOLS are items that are encrypted and decrypted. The ceasar cipher checks agains this symbol.
def encrypt_decrypt(message, key, mode):
    SYMBOLS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890 !?.'
    translated = ''
    
    for symbol in message:
        if symbol in SYMBOLS:
            symbolIndex = SYMBOLS.find(symbol)

            if mode == 'encrypt':
                translatedIndex = symbolIndex + key
            elif mode == 'decrypt':
                translatedIndex = symbolIndex - key

            if translatedIndex >= len(SYMBOLS):
                translatedIndex -= len(SYMBOLS)
            elif translatedIndex < 0:
                translatedIndex += len(SYMBOLS)

            translated += SYMBOLS[translatedIndex]
        else:
            translated += symbol

    return translated

# Create the main window
root = tk.Tk()
root.title("Message Encryptor/Decryptor")

# Mode selection variable between encryption/decryption
mode = StringVar()
# Set default mode to encrypt
mode.set("encrypt")

# Function to get user input and display the result
def process_input():
    message = simpledialog.askstring("Input", "Enter your message:", parent=root)
    key = simpledialog.askinteger("Input", "Enter the key (0-25):", parent=root, minvalue=0, maxvalue=25)

    if message and key is not None:
        processed_message = encrypt_decrypt(message, key, mode.get())
        result_label.config(text=f"Processed Message: {processed_message}")
        pyperclip.copy(processed_message)

# Radio buttons for mode selection
Radiobutton(root, text="Encrypt", variable=mode, value="encrypt").pack()
Radiobutton(root, text="Decrypt", variable=mode, value="decrypt").pack()

# Button to trigger processing
process_button = tk.Button(root, text="Process Message", command=process_input)
process_button.pack()

# Label to display the result
result_label = Label(root, text="Processed Message: None")
result_label.pack()

# Start the GUI event loop
root.mainloop()
