from tkinter import *
from tkinter import messagebox
import yaml
choose_target = False
options_file_path = "options.yaml"


def time_string_to_seconds(time_string:str):
    """Converts a time string in HH:MM:SS format to total seconds.

    Args:
        time_string: The time string (e.g., "00:00:09").

    Returns:
        The total number of seconds represented by the time string.

    Raises:
        ValueError: If the time string is not in the correct format (HH:MM:SS).
    """
    try:
        hours, minutes, seconds = map(int, time_string.split(":"))
        total_seconds = hours * 3600 + minutes * 60 + seconds
        return total_seconds
    except ValueError:
        raise ValueError(f"Invalid time string format: {time_string}")

def update_record_data(option, field, data) -> int:
    """Update date for record in a job

    Args:
        option (_type_): job name
        field (_type_): field to update
        data (_type_): data new to add

    Returns:
        int: -1 if fails; 1 if success
    """
    data_old = None
    try:
        with open(options_file_path, 'r') as yaml_read_io:
            data_old = yaml.safe_load(yaml_read_io)
            option_data:dict = data_old.get(option)
            print(option_data)
            field_data:list = option_data.get(field)
            if field_data == None:
                data_old[option][field] = [data]
            else:
                print(field_data)
                field_data.append(data)
        with open(options_file_path, "w") as yaml_write_io:
            yaml.dump(data_old, yaml_write_io)
        return 1
    except Exception as exp:
        print(exp)
        return -1
        

class Page(Frame):
    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller

class HelloPage(Page):
    # def __init__(self, parent, controller):
    #     Page.__init__(self, parent, controller)
    #     label = Label(self, text="Dashboard", font=('Helvetica', 18, 'bold'))
    #     label.pack(pady=20)
    #     start_button = Button(self, text="Start", command=lambda: controller.show_frame("InputPage"))
    #     start_button.pack(pady=20)
    def __init__(self, parent, controller):
        Page.__init__(self, parent, controller)

        # Initialize variables
        self.seconds = 0
        self.running = False

        # Create timer label
        self.timer_label = Label(self, text="00:00:00", font=("Arial", 50))
        self.timer_label.pack()

        # Create button frame
        self.button_frame = Frame(self)
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
        
        # Create reset button
        self.write_button = Button(self.button_frame, text="Write", command=self.write_result)
        self.write_button.pack(side=LEFT)

        # Frame for options list
        self.options_frame = Frame(self, pady=15)
        self.options_frame.pack(fill=Y, expand=True)

        # Scrollbar for options list
        self.scrollbar = Scrollbar(self.options_frame)
        self.scrollbar.pack(side=RIGHT, fill=Y)

        # Listbox to display options
        self.options_list = Listbox(self.options_frame, yscrollcommand=self.scrollbar.set)
        self.options_list.pack(fill=BOTH, expand=True)
        self.scrollbar.config(command=self.options_list.yview)

        # Button frame
        self.button_frame = Frame(self)
        self.button_frame.pack()

        # Button to choose the selected option
        self.choose_button = Button(self.button_frame, text="Choose", command=self.choose_option)
        self.choose_button.grid(row=0, column=0, padx=10, pady=10)

        # Button to add new option
        self.add_option_button = Button(self.button_frame, text="Add new", command=lambda: controller.show_frame("InputPage"))
        self.add_option_button.grid(row=0, column=1, padx=10, pady=10) 

        # Button to reload new option
        self.add_option_button = Button(self.button_frame, text="Reload new", command=self.load_options)
        self.add_option_button.grid(row=0, column=2, padx=10, pady=10) 
        
        # Label to display the chosen option
        self.chosen_label = Label(self.options_frame, text="Chosen Option:", foreground='red')
        self.chosen_label.pack()
        self.chosen_text = StringVar()  # String variable to store chosen option
        self.chosen_label.config(textvariable=self.chosen_text)  # Bind label to variable
        
        # Load options from file on app launch
        # self.filename = "options.yaml"  # Replace with your file name
        self.load_options()
        print("load me")
        
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
        global choose_target
        choose_target = False
        
        
    def set_timer(self):
        hours, minutes, seconds = self.seconds // 3600, (self.seconds // 60) % 60, self.seconds % 60
        self.timer_label.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        
    def update_timer(self):
        if self.running:
            self.seconds += 1
            self.after(1000, self.update_timer)  # Update every 1 second
        self.set_timer()
        
    def load_options(self):
        self.options_list.delete(0, END) # clean for sure
        try:
            with open(options_file_path, "r") as f:
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
        global choose_target
        if selected_index:
            self.chosen_option = self.options_list.get(selected_index[0])
            self.chosen_text.set(f"You chose: {self.chosen_option}")  # Update label variable
            choose_target = True
        else:
            self.chosen_text.set("Please select an option.")  # Set label for missing selection
    
    
    def write_result(self):
        record_timer = self.timer_label.cget('text')
        total_seconds = time_string_to_seconds(record_timer)
        if update_record_data(self.chosen_option,'lap_lai_count',total_seconds) == 1:
            messagebox.showinfo("Success", "Data saved to file")
            self.write_button.config(state="disabled")
        else:
            messagebox.showinfo("Failed", "Data cannot saved to file")
        print(record_timer)
    
class InputPage(Page):
    def __init__(self, parent, controller):
        Page.__init__(self, parent, controller)
        
        self.create_widgets()
    
    def create_widgets(self):
        Label(self, text="Nhập tên công việc:").grid(row=0, column=0)
        self.ten_cong_viec_entry = Entry(self)
        self.ten_cong_viec_entry.grid(row=0, column=1)
        # self.ten_cong_viec_entry.pack()
        
        fields = [
            "trung_binh_time", "lan_cuoi", "dat_lich_nhac", 
            "ngay_bat_dau", "ngay_ket_thuc", "lap_lai_count", 
            "muc_do_nghiem_trong", "diem_danh_gia"
        ]

        self.entries = {}
        for i, field in enumerate(fields):
            Label(self, text=field).grid(row=i+1, column=0)
            entry = Entry(self)
            entry.grid(row=i+1, column=1)
            self.entries[field] = entry

        self.is_lap_lai_var = BooleanVar()
        Label(self, text="is_lap_lai").grid(row=len(fields)+1, column=0)
        Checkbutton(self, variable=self.is_lap_lai_var).grid(row=len(fields)+1, column=1)
        
        save_button = Button(self, text="Save to YAML", command=self.save_to_yaml)
        save_button.grid(row=len(fields)+2, columnspan=2)
        
        back_button = Button(self, text="Back", command=lambda: self.controller.show_frame("HelloPage"))
        back_button.grid(row=len(fields)+3, columnspan=2)

    def save_to_yaml(self):
        option_name:str= self.ten_cong_viec_entry.get()
        data = {option_name: {field: entry.get() for field, entry in self.entries.items()}}
        data[option_name]['is_lap_lai'] = self.is_lap_lai_var.get()
        
        with open(options_file_path, 'a') as file:
            yaml.dump(data, file)
        
        messagebox.showinfo("Success", "Data saved to output.yaml")

class ViewJobs(Page):
    def __init__(self, parent, controller):
        Page.__init__(self, parent, controller)
        label = Label(self, text="Danh sách công việc", font=('K2D', 18, 'bold'))
        label.pack(pady=20)
        

class App(Tk):
    def __init__(self):
        Tk.__init__(self)
        self.title("Dashboard yourself")

        container = Frame(self)
        container.pack(side="top", fill="both", expand=True)
        
        self.frames = {}
        for F in (HelloPage, InputPage):
            page_name = F.__name__
            frame = F(parent=container, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        
        self.show_frame("HelloPage")

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()

if __name__ == "__main__":
    app = App()
    app.mainloop()
