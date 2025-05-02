import tkinter as tk
from gui import PasswordManagerGUI

def main():
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 