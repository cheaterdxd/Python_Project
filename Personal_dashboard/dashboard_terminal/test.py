import tkinter as tk
from tkinter import messagebox
import yaml

# Function to save data to a YAML file
def save_to_yaml():
    data = {
        'option1': {
            'trung_binh_time': trung_binh_time_entry.get(),
            'lan_cuoi': lan_cuoi_entry.get(),
            'dat_lich_nhac': dat_lich_nhac_entry.get(),
            'ngay_bat_dau': ngay_bat_dau_entry.get(),
            'ngay_ket_thuc': ngay_ket_thuc_entry.get(),
            'is_lap_lai': is_lap_lai_var.get(),
            'lap_lai_count': lap_lai_count_entry.get(),
            'muc_do_nghiem_trong': muc_do_nghiem_trong_entry.get(),
            'diem_danh_gia': diem_danh_gia_entry.get()
        }
    }

    with open('output.yaml', 'w') as file:
        yaml.dump(data, file)
    
    messagebox.showinfo("Success", "Data saved to output.yaml")

# Create the main window
root = tk.Tk()
root.title("YAML Input Form")

# Create labels and entries for each field
tk.Label(root, text="trung_binh_time").grid(row=0, column=0)
trung_binh_time_entry = tk.Entry(root)
trung_binh_time_entry.grid(row=0, column=1)

tk.Label(root, text="lan_cuoi").grid(row=1, column=0)
lan_cuoi_entry = tk.Entry(root)
lan_cuoi_entry.grid(row=1, column=1)

tk.Label(root, text="dat_lich_nhac").grid(row=2, column=0)
dat_lich_nhac_entry = tk.Entry(root)
dat_lich_nhac_entry.grid(row=2, column=1)

tk.Label(root, text="ngay_bat_dau").grid(row=3, column=0)
ngay_bat_dau_entry = tk.Entry(root)
ngay_bat_dau_entry.grid(row=3, column=1)

tk.Label(root, text="ngay_ket_thuc").grid(row=4, column=0)
ngay_ket_thuc_entry = tk.Entry(root)
ngay_ket_thuc_entry.grid(row=4, column=1)

tk.Label(root, text="is_lap_lai").grid(row=5, column=0)
is_lap_lai_var = tk.BooleanVar()
is_lap_lai_checkbox = tk.Checkbutton(root, variable=is_lap_lai_var)
is_lap_lai_checkbox.grid(row=5, column=1)

tk.Label(root, text="lap_lai_count").grid(row=6, column=0)
lap_lai_count_entry = tk.Entry(root)
lap_lai_count_entry.grid(row=6, column=1)

tk.Label(root, text="muc_do_nghiem_trong").grid(row=7, column=0)
muc_do_nghiem_trong_entry = tk.Entry(root)
muc_do_nghiem_trong_entry.grid(row=7, column=1)

tk.Label(root, text="diem_danh_gia").grid(row=8, column=0)
diem_danh_gia_entry = tk.Entry(root)
diem_danh_gia_entry.grid(row=8, column=1)

# Create a button to save the data
save_button = tk.Button(root, text="Save to YAML", command=save_to_yaml)
save_button.grid(row=9, columnspan=2)

# Start the Tkinter event loop
root.mainloop()
