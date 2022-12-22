import sqlite3
import socket
import csv
import customtkinter as ctk
import paramiko
import multiprocessing
import time
import sys
from tkinter import filedialog
from functools import partial
from typing import Tuple, List, Dict

# To compile
# pyinstaller '.\SSH Tool.py' --onedir --name "SSH Tool" --add-data "C:\Users\ms927411\PycharmProjects\networking\venv\Lib\site-packages\customtkinter;customtkinter/" --noconfirm --clean --windowed

output_list = []


# Function to handle the SSH connection and command execution
def ssh_command(ip, username, password, command, queue):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    output = {"Hostname": ip,
              "Command": command}

    # Try to connect three times
    for i in range(3):
        try:
            # Connect
            client.connect(ip, username=username, password=password)
            # Run command
            stdin, stdout, stderr = client.exec_command(command)
            # Add data to the output dictionary
            output["Output"] = stdout.read().decode()
            # Put data onto the queue to be read later
            queue.put(output)
            break

        # todo rewrite the following into an exception group

        except paramiko.ssh_exception.NoValidConnectionsError:
            if i == 2:
                print(f"Failed to SSH connect to {ip}")
                output["Output"] = f"Failed to connect to after three attempts"
        except socket.gaierror:
            if i == 2:
                print(f"Failed to find {ip} after three attempts")
                output["Output"] = f"Failed to find {ip} after three attempts"
        except TimeoutError:
            if i == 2:
                print(f"Host {ip} failed to respond")
                output["Output"] = f"Host failed to respond"
        except paramiko.ssh_exception.AuthenticationException:
            if i == 2:
                print(f"Authentication failed when connecting to {ip}")
                output["Output"] = f"Authentication failed"
        except Exception as e:
            if i == 2:
                print(f"An error occurred when connecting to {ip} : {e}")
                output["Output"] = f"An error occurred: {e}"

    queue.put(output)
    client.close()


# Function that creates a new process for each ip and command
def run_commands(ips, username, password, commands, queue):
    # GUI Progress bar variable
    progress_bar_value = 0
    loading_bar.set(progress_bar_value)
    root.update()
    # Create a list of processes
    processes = []

    # Iterate over the list of IPs
    for ip in ips:
        # Ignore empty ips
        if ip.strip() == "":
            continue
        for command in commands:
            # Ignore empty commands
            if command.strip() == "":
                continue
            # Create a new process and add it to the list
            p = multiprocessing.Process(target=ssh_command, args=(ip, username, password, command, queue), daemon=True)
            processes.append(p)

    # Amount of progress bar to fill up when each process is finished
    # Save the last 10% for displaying the data
    progress_per_process: float = (0.9 / len(processes)) / 2

    # Start the processes
    for p in processes:
        p.start()
        # Update progress bar
        time.sleep(0.01)
        progress_bar_value += progress_per_process
        loading_bar.set(progress_bar_value)
        root.update()

    # Wait for the processes to complete
    for p in processes:
        p.join()
        progress_bar_value += progress_per_process
        loading_bar.set(progress_bar_value)
        root.update()


# Get data from a text file
def get_data_from_file(filename) -> str:
    with open(filename, 'r') as f:
        data = f.read()
    return data


# Select a file using file explorer
def select_a_file() -> str:
    return filedialog.askopenfilename(title="Select File",
                                      initialdir=".",
                                      filetypes=[("Text files", "*.txt")])


# Get data from a file and update an entry box
def update_entry_from_file(entry_widget: ctk.CTkTextbox):
    file = select_a_file()
    data = get_data_from_file(file)

    current_text = entry_widget.get("1.0", "end").strip()
    entry_widget.delete("1.0", "end")
    entry_widget.insert("1.0", f"{current_text}\n{data}".strip())


# Get input from the GUI
def get_input() -> Tuple[List[str], str, str, List[str]]:
    username = username_entry.get().strip()
    password = password_entry.get().strip()
    commands = commands_entry.get("1.0", "end").strip().split("\n")
    ip_addrs = ip_addresses_entry.get("1.0", "end").strip().split("\n")
    return ip_addrs, username, password, commands


# Format the output data into a text format
def format_to_text(data: List[Dict]) -> str:
    # [{"Hostname": *, "Command": *, "Output": *}, ]
    formatted_text = ""
    for index, dictionary in enumerate(data):
        # For an unknown reason, the dictionaries are duplicated
        # Therefore we have to do one or the other
        # if index % 2 == 0:
        formatted_text += f"\n{dictionary.get('Hostname')} :: {dictionary.get('Command')} ::" \
                          f"\n{dictionary.get('Output')}"

    return formatted_text


# Start the process of running all the commands then write the result to the output text
def start():
    global output_list
    output_list = []
    output_queue = multiprocessing.Queue()

    run_commands(*get_input(), queue=output_queue)
    for _ in range(output_queue.qsize()):
        output_list.append(output_queue.get())

    # Remove duplicate items and sort list by hostnames/IPs
    output_list = sorted(output_list[::2], key=lambda d: d["Hostname"])

    # Get the text output
    text = format_to_text(output_list)
    # Clear the output box
    output_text.configure(state="normal")
    output_text.delete("1.0", "end")
    # Display output
    output_text.insert("1.0", text)
    # Finish loading bar
    loading_bar.set(1)
    output_text.configure(state="disable")
    enable_save_button(None)
    output_queue.close()


# Using file explorer, user selects a location and filename
def get_save_file_name(filetype_name: list, filetype_extension: str) -> str:
    return filedialog.asksaveasfilename(title="Save File",
                                        initialdir=".",
                                        filetypes=filetype_name,
                                        defaultextension=filetype_extension)


# Format the dictionary into a csv format and save to a user selected file
def write_to_csv(data: List[dict]):
    filename = get_save_file_name([("CSV", ".csv")], ".csv")
    fields = ["Hostname", "Command", "Output"]
    with open(filename, 'a', newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)


def write_to_sql(data: List[dict]):
    filename = get_save_file_name([("SQLite Database", ".db")], ".db")
    # Connect to database
    conn = sqlite3.connect(filename)
    # Create a cursor
    cursor = conn.cursor()
    # Create the table
    cursor.execute("CREATE TABLE IF NOT EXISTS commands (Hostname TEXT, Command TEXT, Output TEXT)")
    conn.commit()
    cursor = conn.cursor()
    item: dict
    for item in data:
        # Add a row to the table
        cursor.execute("INSERT INTO commands (Hostname, Command, Output) VALUES (?, ?, ?)",
                       (item["Hostname"], item["Command"], item["Output"]))
    conn.commit()


# For GUI button - saves a file with the output data
def save_to_file():
    choice = file_choice.get()
    data = output_list
    if len(data) == 0:
        return
    try:
        if choice == "File Type":
            # Default value of drop down => Don't save
            return
        elif choice == "TXT":
            with open(get_save_file_name([("Text File", ".txt")], ".txt"), 'a') as f:
                f.write(format_to_text(data))
        elif choice == "CSV":
            write_to_csv(data)
        elif choice == "SQL":
            write_to_sql(data)
    except FileNotFoundError:
        return


# When enable_save_button is run by the start() function it correctly destroys the old button and replaces it. But when
# Enables and changes the colour of save_file_button when there is data to save and a file type selected
def enable_save_button(event, attempt=0):
    print(file_choice.get(), len(output_list))
    if (file_choice.get() != "File Type" or attempt == 1) and len(output_list) > 0:
        global save_file_button
        save_file_button.configure(state="normal")
        save_file_button.destroy()
        save_file_button = ctk.CTkButton(root, text="Save", command=save_to_file)
        save_file_button.grid(row=4, column=5, padx=(0, 10), pady=(5, 10), sticky="NSEW")
        root.update()
    if attempt == 0 and event is not None:
        enable_save_button(event, 1)


if __name__ == "__main__":
    # How can I edit this code to make the GUI resize dynamically when the window is resized by the user?
    # Allows program to be compiled to .exe
    multiprocessing.freeze_support()

    # Create GUI

    # GUI Theming
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    # Window Settings
    root = ctk.CTk()
    root.title("SSH Tool")
    root.minsize(550, 400)

    # Configure columns
    root.columnconfigure(0, weight=0)
    root.columnconfigure(1, weight=20)
    root.columnconfigure(3, weight=60)
    root.columnconfigure(4, weight=5)
    root.columnconfigure(5, weight=5)

    # Configure rows
    root.rowconfigure(0, weight=0)
    root.rowconfigure(1, weight=0)
    root.rowconfigure(2, weight=4)
    root.rowconfigure(3, weight=4)
    root.rowconfigure(4, weight=0)

    # Create GUI widgets

    # Username
    username_label = ctk.CTkLabel(root, text="Username:", )
    username_label.grid(row=0, column=0, sticky="W", padx=10)

    username_entry = ctk.CTkEntry(root, placeholder_text="Username")
    username_entry.grid(row=0, column=1, sticky="EW", padx=(0, 10), pady=5)

    # Password
    password_label = ctk.CTkLabel(root, text="Password:")
    password_label.grid(row=1, column=0, sticky="W", padx=10)

    password_entry = ctk.CTkEntry(root, show="*", placeholder_text="Password")
    password_entry.grid(row=1, column=1, sticky="EW", padx=(0, 10), pady=(0, 5))

    # IPs / Hostnames
    ip_addresses_label = ctk.CTkLabel(root, text="IPs and\nHostnames:")
    ip_addresses_label.grid(row=2, column=0, sticky="W", padx=10)

    ip_addresses_file_button = ctk.CTkButton(root, text="Open File", width=5)
    ip_addresses_file_button.grid(row=2, column=0, sticky="S", padx=10, pady=5)

    ip_addresses_entry = ctk.CTkTextbox(root, wrap="none", )
    ip_addresses_entry.grid(row=2, column=1, pady=5, padx=(0, 10), sticky="NSEW")

    ip_addresses_file_button.configure(command=partial(update_entry_from_file, ip_addresses_entry))

    # Commands
    commands_label = ctk.CTkLabel(root, text="Commands:")
    commands_label.grid(row=3, column=0, sticky="W", padx=10, )

    commands_file_button = ctk.CTkButton(root, text="Open File", width=5)
    commands_file_button.grid(row=3, column=0, sticky="S", padx=10, pady=5)

    commands_entry = ctk.CTkTextbox(root, wrap="none")
    commands_entry.grid(row=3, column=1, pady=5, padx=(0, 10), sticky="NSEW")

    commands_file_button.configure(command=partial(update_entry_from_file, commands_entry))

    # Submit
    submit_button = ctk.CTkButton(root, text="Run Commands", command=start)
    submit_button.grid(row=4, column=1, pady=(5, 10), padx=(0, 10), sticky="NSEW")

    # Line separating input and output
    seperator = ctk.CTkFrame(root, border_width=0, width=3, fg_color="#3B3B3B")
    seperator.grid(row=0, column=2, rowspan=5, padx=(3, 13), pady=(5, 10), sticky="NS")

    # Output Text
    output_label = ctk.CTkLabel(root, text="OUTPUT", )
    output_label.grid(row=0, column=3, columnspan=3, padx=(0, 10), sticky="NSEW")

    output_text = ctk.CTkTextbox(root, width=500, state="normal")
    output_text.grid(row=1, column=3, rowspan=3, columnspan=3, padx=(0, 10), pady=(0, 5), sticky="NSEW")
    output_text.configure(state="disable")  # Stops user from typing in output box

    # A loading bar that's updated when "Run Commands" is clicked
    # Updates dynamically
    loading_bar = ctk.CTkProgressBar(root, width=260)
    loading_bar.set(0)
    loading_bar.grid(row=4, column=3, pady=(5, 10), sticky="EW")

    # Save Output to File
    file_choice = ctk.StringVar()
    file_choice.set("File Type")
    file_options = ["CSV", "Text", "SQLite"]
    file_choice_dropdown = ctk.CTkOptionMenu(root, values=file_options, variable=file_choice,
                                             dynamic_resizing=False)
    file_choice_dropdown.grid(row=4, column=4, padx=10, pady=(5, 10), sticky="NSEW")
    file_choice_dropdown.bind("<Button-1>", enable_save_button)

    # Depending on the option selected in the above drop down, format the data and save it to the chosen file type
    save_file_button = ctk.CTkButton(root, text="Save", command=save_to_file, hover=False)
    save_file_button.grid(row=4, column=5, padx=(0, 10), pady=(5, 10), sticky="NSEW")
    save_file_button.configure(state="disable", fg_color="#3B3B3B", require_redraw=True)

    # Run GUI
    root.mainloop()

# todo Write docstrings for all functions
