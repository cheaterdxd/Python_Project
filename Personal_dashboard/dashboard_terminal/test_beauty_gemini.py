import tkinter as tk


class HelloApp:
  def __init__(self, master):
    self.master = master
    master.title("Hello App")

    # Define color scheme (replace with your preferences)
    self.bg_color = "#f3e9d2"  # Light background
    self.text_color1 = "#2c497f"  # Dark text color
    self.text_color2 = "#ea2b1f"  # Red text color (accent)
    self.button_color = "#edae49"  # Orange button color

    # Create main frame with grid layout
    self.main_frame = tk.Frame(master, bg=self.bg_color)
    self.main_frame.grid(row=0, column=0, sticky=tk.N+tk.S+tk.E+tk.W)

    # Create toolbars with colored labels
    self.toolbar1 = tk.Frame(self.main_frame, bg=self.bg_color, height=30)
    self.toolbar1.grid(row=0, column=0, sticky=tk.W+tk.E, columnspan=2)  # Span two columns
    self.toolbar1_label = tk.Label(self.toolbar1, text="Menu", fg=self.text_color1, bg=self.bg_color, font=("K2D", 12))
    self.toolbar1_label.pack(side=tk.LEFT, padx=10)

    self.toolbar2 = tk.Frame(self.main_frame, bg=self.bg_color, height=30)
    self.toolbar2.grid(row=1, column=0, sticky=tk.W+tk.E, columnspan=2)  # Span two columns
    self.toolbar2_label = tk.Label(self.toolbar2, text="Options", fg=self.text_color1,bg=self.bg_color, font=("K2D", 12))
    self.toolbar2_label.pack(side=tk.LEFT, padx=10)

    # Create hello label with K2D font and red color
    self.hello_label = tk.Label(self.main_frame, text="Hello, World!", fg=self.text_color2, bg=self.bg_color, font=("K2D", 24))
    self.hello_label.grid(row=2, column=0, columnspan=2, pady=20, sticky=tk.W+tk.E)  # Expand horizontally

    # Create rounded start button with custom color and K2D font
    self.start_button = tk.Button(
        self.main_frame,
        text="Start",
        fg=self.text_color1,
        bg=self.button_color,
        font=("K2D", 14),
        command=self.start_clicked,
        borderwidth=0,
        highlightthickness=0,
        relief=tk.RAISED
    )
    self.start_button.grid(row=3, column=0, columnspan=2, pady=20, sticky=tk.W+tk.E)  # Expand horizontally

  def start_clicked(self):
    print("Start button clicked!")
    # You can add functionality here

# Run the application
root = tk.Tk()
root.geometry("500x300")  # Optional: Set initial window size
app = HelloApp(root)
root.mainloop()
