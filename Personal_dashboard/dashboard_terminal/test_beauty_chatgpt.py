import tkinter as tk
from tkinter import font

# Define the colors from the first set (flat design)
bg_color = '#f9edcc'  # Light cream
button_color = '#ea2b1f'  # Red
toolbar_color = '#61210f'  # Dark red for toolbar
text_color = 'black'  # Text color for labels and buttons

# Function to start the application
def start_application():
    # Replace this with your application logic
    print("Application started!")

# Function to open a new file (example function)
def open_file():
    print("Opening file...")

# Function to save the current file (example function)
def save_file():
    print("Saving file...")

# Function to exit the application
def exit_application():
    root.destroy()

# Create the main application window
root = tk.Tk()
root.title("Hello App")
root.geometry("300x300")
root.configure(bg=bg_color)  # Set background color for the window

# Allow elements to resize with the window
root.pack_propagate(False)

# Load the K2D font (ensure the font file is available in your system)
k2d_font = font.Font(family='K2D', size=12)

# Create a frame for the toolbar
toolbar_frame = tk.Frame(root, bg=toolbar_color)
toolbar_frame.pack(side=tk.TOP, fill=tk.X)

# Create buttons for the toolbar with K2D font and smaller size
toolbar_buttons = [
    ("Open", open_file),
    ("Save", save_file),
    ("Exit", exit_application)
]

for text, command in toolbar_buttons:
    button = tk.Button(toolbar_frame, text=text, bg=button_color, fg='white', font=k2d_font, padx=8, pady=4, bd=0, command=command)
    button.pack(side=tk.LEFT, padx=5, pady=5)

# Create a label for the toolbar with K2D font
toolbar_label = tk.Label(toolbar_frame, text="Toolbar", bg=toolbar_color, fg=text_color, font=("K2D", 16, "bold"))
toolbar_label.pack(side=tk.LEFT, padx=10, pady=10)

# Create a start button with K2D font and smaller size
start_button = tk.Button(root, text="Start", bg=button_color, fg='white', font=k2d_font, padx=10, pady=5, bd=0, command=start_application)
start_button.pack(pady=20)

# Function to handle window resizing
def on_resize(event):
    # Adjust toolbar frame width to match window width
    toolbar_frame.configure(width=event.width)

# Bind the resize function to the window resizing
root.bind("<Configure>", on_resize)

# Remove window decorations (title bar)
# root.overrideredirect(True)

# Move the window by dragging the toolbar
def start_move(event):
    root.x = event.x
    root.y = event.y

def stop_move(event):
    root.x = None
    root.y = None

def do_move(event):
    deltax = event.x - root.x
    deltay = event.y - root.y
    x = root.winfo_x() + deltax
    y = root.winfo_y() + deltay
    root.geometry(f"+{x}+{y}")

toolbar_label.bind("<ButtonPress-1>", start_move)
toolbar_label.bind("<ButtonRelease-1>", stop_move)
toolbar_label.bind("<B1-Motion>", do_move)

# Run the Tkinter event loop
root.mainloop()
