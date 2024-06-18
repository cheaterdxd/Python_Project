        # # Label for instructions
        # label = Label(master, text="Enter new options (one per line):")
        # label.pack()

        # # Text area for multiline input
        # new_options_text_area = Text(master, width=30, height=5)
        # new_options_text_area.pack()

        # # Button to add the option
        # add_button = Button(master, text="Add", command=self.add_option)
        # add_button.pack()
        
    # def add_option(self):
    #     """Gets user input from the text area and writes it to the options.txt file."""
    #     new_option = self.new_options_text_area.get("1.0", END).strip()  # Get text from 1.0 (start) to END, strip whitespace
    #     if new_option:  # Check if user entered something
    #         with open(self.filename, "a") as f:
    #             f.write(f"{new_option}\n")  # Write with newline character
    #             self.new_options_text_area.delete("1.0", END)  # Clear text area after adding
    #             print(f"Option added to the file:\n{new_option}")