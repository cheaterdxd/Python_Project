print("Terminal dashboard")

import curses


def choose(options:list):
    """Choose by cursor \n
    Tham so:
    - options: danh sach cac option [list]
    """
    # Initialize curses screen
    screen = curses.initscr()
    curses.cbreak()
    screen.keypad(True)

    selected_index = 0

    # Loop until user exits
    while True:
        # Clear screen
        screen.clear()

        # Print options with highlighting for selected option
        for i, option in enumerate(options):
            if i == selected_index:
                # Highlight selected option with bold text
                screen.addstr(f"--> {option}\n")
            else:
                screen.addstr(f"{option}\n")

        # Refresh screen
        screen.refresh()

        # Get user input
        key = screen.getch()

        # Handle arrow key navigation
        if key in (curses.KEY_UP, ord('k')):
            selected_index = (selected_index - 1) % len(options)  # Wrap around
        elif key in (curses.KEY_DOWN, ord('j')):
            selected_index = (selected_index + 1) % len(options)  # Wrap around
        elif key == ord('q'):  # Exit on 'q' press
            break
  

    # Final message
    screen.clear()
    screen.addstr(f"You chose: {options[selected_index]}\n")
    screen.refresh()
    curses.endwin()
    return options[selected_index]
def main():
    options = ["Option 1", "Option 2", "Option 3"]
    print(choose(options))

if __name__ == "__main__":
    main()
