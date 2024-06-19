import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

def start_button_clicked():
    # Add your logic here when the Start button is clicked
    print("Start button clicked!")

# Create the main window
root = ttk.Window()

# Add a label
label = ttk.Label(root, text="Contact Information", font=("Arial", 20, "bold"))
label.pack(pady=30)

# Create a frame for entry widgets
frame = ttk.Frame(root)
frame.pack(pady=15, padx=10, fill="x")

# Add entry widgets
name_entry = ttk.Entry(frame)
name_entry.pack(pady=5)
email_entry = ttk.Entry(frame)
email_entry.pack(pady=5)

# Add the Start button
start_button = ttk.Button(root, text="Start", command=start_button_clicked)
start_button.pack(pady=20)

root.mainloop()  # Run the Tkinter event loop
