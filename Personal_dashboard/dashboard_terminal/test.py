import tkinter as tk
import yaml

class OptionChooser:
  def __init__(self, master):
    self.master = master
    master.title("Option Chooser")

    # Frame for options list
    self.options_frame = tk.Frame(master)
    self.options_frame.pack(fill=tk.Y, expand=True)

    # Scrollbar for options list
    self.scrollbar = tk.Scrollbar(self.options_frame)
    self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # Listbox to display options
    self.options_list = tk.Listbox(self.options_frame, yscrollcommand=self.scrollbar.set)
    self.options_list.pack(fill=tk.BOTH, expand=True)
    self.scrollbar.config(command=self.options_list.yview)

    # Button frame
    self.button_frame = tk.Frame(master)
    self.button_frame.pack()

    # Button to choose the selected option
    self.choose_button = tk.Button(self.button_frame, text="Choose", command=self.choose_option)
    self.choose_button.pack(side=tk.LEFT)

    # Label to display the chosen option
    self.chosen_label = tk.Label(master, text="Chosen Option:")
    self.chosen_label.pack()
    self.chosen_text = tk.StringVar()  # String variable to store chosen option
    self.chosen_label.config(textvariable=self.chosen_text)

    # Load options from YAML file on app launch
    self.filename = "options.yaml"  # Replace with your file name

    self.load_options()

  def load_options(self):
    try:
        with open(self.filename, "r") as f:
            data = yaml.safe_load(f)
        options = list(data.keys())  # Extract option names as keys
        print(options)
        for option in options:
            self.options_list.insert(tk.END, option.strip())
    except FileNotFoundError:
        print(f"Error: File '{self.filename}' not found.")
        return []
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file: {e}")
        return []

  def choose_option(self):
    selected_index = self.options_list.curselection()
    if selected_index:
      chosen_option = self.options_list.get(selected_index[0])
      self.chosen_text.set(f"You chose: {chosen_option}")  # Update label variable
    else:
      self.chosen_text.set("Please select an option.")  # Set label for missing selection

    # You can access the full option data using self.options[chosen_option]

# Create main window and run app
root = tk.Tk()
app = OptionChooser(root)
root.mainloop()
