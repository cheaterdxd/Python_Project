from tkinter import *
import os

import yaml


choose_target = False

class MyApp:
    def __init__(self, master):
        self.master = master
        master.title("My Dashboard")

        # Initialize variables
        self.seconds = 0
        self.running = False

        # Create timer label
        self.timer_label = Label(master, text="00:00:00", font=("Arial", 50))
        self.timer_label.pack()

        # Create button frame
        self.button_frame = Frame(master)
        self.button_frame.pack()

        # Create start button
        self.start_button = Button(self.button_frame, text="Start", command=self.start_timer)
        self.start_button.pack(side=LEFT)

        # Create stop button
        self.stop_button = Button(self.button_frame, text="Stop", command=self.stop_timer, state="disabled")
        self.stop_button.pack(side=LEFT)

        # Create reset button
        self.reset_button = Button(self.button_frame, text="Reset", command=self.reset_timer)
        self.reset_button.pack(side=LEFT)

        # Frame for options list
        self.options_frame = Frame(master, pady=15)
        self.options_frame.pack(fill=Y, expand=True)

        # Scrollbar for options list
        self.scrollbar = Scrollbar(self.options_frame)
        self.scrollbar.pack(side=RIGHT, fill=Y)

        # Listbox to display options
        self.options_list = Listbox(self.options_frame, yscrollcommand=self.scrollbar.set)
        self.options_list.pack(fill=BOTH, expand=True)
        self.scrollbar.config(command=self.options_list.yview)

        # Button frame
        self.button_frame = Frame(master)
        self.button_frame.pack()

        # Button to choose the selected option
        self.choose_button = Button(self.button_frame, text="Choose", command=self.choose_option)
        self.choose_button.pack(side=LEFT)
        
        # Label to display the chosen option
        self.chosen_label = Label(master, text="Chosen Option:", foreground='red')
        self.chosen_label.pack()
        self.chosen_text = StringVar()  # String variable to store chosen option
        self.chosen_label.config(textvariable=self.chosen_text)  # Bind label to variable
        
        # Load options from file on app launch
        self.filename = "options.yaml"  # Replace with your file name
        self.load_options()
        
        # Label for instructions
        label = Label(master, text="Enter new options (one per line):")
        label.pack()

        # Text area for multiline input
        new_options_text_area = Text(master, width=30, height=5)
        new_options_text_area.pack()

        # Button to add the option
        add_button = Button(master, text="Add", command=self.add_option)
        add_button.pack()
        
    def add_option(self):
        """Gets user input from the text area and writes it to the options.txt file."""
        new_option = self.new_options_text_area.get("1.0", END).strip()  # Get text from 1.0 (start) to END, strip whitespace
        if new_option:  # Check if user entered something
            with open(self.filename, "a") as f:
                f.write(f"{new_option}\n")  # Write with newline character
                self.new_options_text_area.delete("1.0", END)  # Clear text area after adding
                print(f"Option added to the file:\n{new_option}")
        
    def start_timer(self):
        if choose_target == False:
            self.chosen_text.set("Please select an option.")  # Set label for missing selection
        elif not self.running:
            self.running = True
            self.update_timer()
            self.start_button.config(state="disabled")
            self.reset_button.config(state="disabled")
            self.stop_button.config(state="active")

    def stop_timer(self):
        self.running = False
        self.start_button.config(text="Continue")
        self.start_button.config(state="active")
        self.reset_button.config(state="active")
        

    def reset_timer(self):
        self.seconds = 0
        self.update_timer()
        self.start_button.config(text="Start")
        self.start_button.config(state="active")
        
        
    def set_timer(self):
        hours, minutes, seconds = self.seconds // 3600, (self.seconds // 60) % 60, self.seconds % 60
        self.timer_label.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        
    def update_timer(self):
        if self.running:
            self.seconds += 1
            self.master.after(1000, self.update_timer)  # Update every 1 second
        self.set_timer()
        
    def load_options(self):
        try:
            with open(self.filename, "r") as f:
                data = yaml.safe_load(f)
            options = list(data.keys())  # Extract option names as keys
            print(options)
            for option in options:
                self.options_list.insert(END, option.strip())
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
            choose_target = True
        else:
            self.chosen_text.set("Please select an option.")  # Set label for missing selection
            
# Create main window and run app
root = Tk()
app = MyApp(root)
root.mainloop()
