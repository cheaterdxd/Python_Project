import tkinter as tk
import yaml


class YamlApp:
    def __init__(self, master, filename):
        self.master = master
        master.title("YAML Data Viewer")

        # Load data from YAML file
        self.data = self.load_data(filename)

        # Create frames for layout
        self.data_frame = tk.Frame(master)
        self.data_frame.pack(fill=tk.BOTH, expand=True)
        self.button_frame = tk.Frame(master)
        self.button_frame.pack()

        # Create labels for column headers
        self.name_label = tk.Label(self.data_frame, text="Test Name", width=15)
        self.name_label.grid(row=0, column=0, padx=5, pady=5)
        self.b1_label = tk.Label(self.data_frame, text="b1", width=10)
        self.b1_label.grid(row=0, column=1, padx=5, pady=5)
        self.b2_label = tk.Label(self.data_frame, text="b2", width=10)
        self.b2_label.grid(row=0, column=2, padx=5, pady=5)

        # Create Listbox for table view
        self.data_table = tk.Listbox(self.data_frame, width=40, height=10)
        self.data_table.grid(row=1, columnspan=3, padx=5, pady=5, sticky=tk.N+tk.S+tk.E+tk.W)

        # Button to refresh data (optional)
        self.refresh_button = tk.Button(self.button_frame, text="Refresh", command=self.refresh_data)
        self.refresh_button.pack(padx=5, pady=5)

        # Fill table with data on load
        self.fill_data_table()

    def load_data(self, filename):
        try:
            with open(filename, "r") as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print(f"Error: File '{filename}' not found.")
            return {}
        except yaml.YAMLError as e:
                print(f"Error parsing YAML file: {e}")
        return {}

    def fill_data_table(self):
        # Insert header row
        self.data_table.insert(tk.END, f"{'Option Name':<15} {'ngay_bat_dau':<10} {'ngay_ket_thuc':<10}")

        for name, test_data in self.data.items():
            # Insert test name (assuming 'name' is the key for the data)
            self.data_table.insert(tk.END, f"{name:<15}")

            # Insert property values from 'test_data' dictionary
            data1 = test_data.get('ngay_bat_dau')
            data2 = test_data.get('ngay_ket_thuc')
            if data1 == None:
                data1 = ""
            if data2 == None:
                data2 = ""
            self.data_table.insert(tk.END, f"{data1:<10}")
            self.data_table.insert(tk.END, f"{data2:<10}")

    def refresh_data(self):
        # Implement logic to reload data from file (optional)
        # You can clear the table and call fill_data_table()
        self.data_table.delete(0, tk.END)
        self.fill_data_table()

# Example usage
root = tk.Tk()
app = YamlApp(root, "options.yaml")  # Replace with your filename
root.mainloop()
