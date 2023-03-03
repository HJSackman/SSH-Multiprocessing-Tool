import copy
import csv
import multiprocessing
import socket
import threading
import time
from functools import partial
from pathlib import Path
from tkinter import filedialog
import customtkinter as ctk
import logging
from typing import List, Iterable, Dict
import paramiko
import re


class Application(ctk.CTkFrame):
    def __init__(self, master, log):
        self.progress_per_process = None
        self.running = False
        self.logger = log
        self.results = None
        self.threads = []
        # Used for updating the loading bar
        self.loading_bar_queue = multiprocessing.Queue()

        # Set up master window
        super().__init__(master)
        self.master = master
        self.master.title("Harry's SSH Tool")
        self.master.minsize(550, 400)

        # Allows the Frame to expand as the window does
        self.master.columnconfigure(0, weight=1)
        self.master.rowconfigure(0, weight=1)
        # sticky="NSEW" makes sure the Frame expands when the window does.
        self.grid(column=0, row=0, sticky="NSEW")

        # Set up this Frame
        self.configure_columns()
        self.configure_rows()

        # Create widgets
        # Username
        self.username_label = ctk.CTkLabel(self, text="Username:", )
        self.username_label.grid(row=0, column=0, sticky="W", padx=10)

        self.username_entry = ctk.CTkEntry(self, placeholder_text="Username")
        self.username_entry.grid(row=0, column=1, sticky="EW", padx=(0, 10), pady=5)

        # Password
        self.password_label = ctk.CTkLabel(self, text="Password:")
        self.password_label.grid(row=1, column=0, sticky="W", padx=10)

        self.password_entry = ctk.CTkEntry(self, show="*", placeholder_text="Password")
        self.password_entry.grid(row=1, column=1, sticky="EW", padx=(0, 10), pady=(0, 5))

        # IPs / Hostnames
        self.ip_addresses_label = ctk.CTkLabel(self, text="IPs and\nHostnames:")
        self.ip_addresses_label.grid(row=2, column=0, sticky="W", padx=10)

        self.ip_addresses_file_button = ctk.CTkButton(self, text="Open File", width=5)
        self.ip_addresses_file_button.grid(row=2, column=0, sticky="S", padx=10, pady=5)

        self.ip_addresses_entry = ctk.CTkTextbox(self, wrap="none", )
        self.ip_addresses_entry.grid(row=2, column=1, pady=5, padx=(0, 10), sticky="NSEW")

        self.ip_addresses_file_button.configure(command=partial(Application.update_entry_from_file,
                                                                self.ip_addresses_entry))

        # Commands
        self.commands_label = ctk.CTkLabel(self, text="Commands:")
        self.commands_label.grid(row=3, column=0, sticky="W", padx=10, )

        self.commands_file_button = ctk.CTkButton(self, text="Open File", width=5)
        self.commands_file_button.grid(row=3, column=0, sticky="S", padx=10, pady=5)

        self.commands_entry = ctk.CTkTextbox(self, wrap="none")
        self.commands_entry.grid(row=3, column=1, pady=5, padx=(0, 10), sticky="NSEW")

        self.commands_file_button.configure(command=partial(Application.update_entry_from_file,
                                                            self.commands_entry))

        # Submit
        self.submit_button = ctk.CTkButton(self, text="Run Commands", command=self.start_thread)
        self.submit_button.grid(row=4, column=1, pady=(5, 10), padx=(0, 10), sticky="NSEW")

        # Line separating input and output
        self.seperator = ctk.CTkFrame(self, border_width=0, width=3, fg_color="#3B3B3B")
        self.seperator.grid(row=0, column=2, rowspan=5, padx=(3, 13), pady=(5, 10), sticky="NS")

        # Output Text
        self.output_label = ctk.CTkLabel(self, text="OUTPUT", )
        self.output_label.grid(row=0, column=3, columnspan=3, padx=(0, 10), sticky="NSEW")

        self.output_text = ctk.CTkTextbox(self, width=500, state="normal")
        self.output_text.grid(row=1, column=3, rowspan=3, columnspan=3, padx=(0, 10), pady=(0, 5), sticky="NSEW")
        self.output_text.configure(state="disable")  # Stops user from typing in output box

        # A loading bar that's updated when "Run Commands" is clicked
        self.loading_bar = ctk.CTkProgressBar(self, width=260)
        # Starts at 0
        self.loading_bar.set(0)
        self.loading_bar.grid(row=4, column=3, pady=(5, 10), sticky="EW")

        # Save Output to File
        self.file_choice = ctk.StringVar()
        self.file_choice.set("File Type")
        # todo - expand options
        self.file_options = ["CSV", "Text"]
        self.file_choice_dropdown = ctk.CTkOptionMenu(self, values=self.file_options, variable=self.file_choice,
                                                      dynamic_resizing=False)
        self.file_choice_dropdown.grid(row=4, column=4, padx=10, pady=(5, 10), sticky="NSEW")
        self.file_choice_dropdown.bind("<Button-1>", lambda event: self.enable_save_button(event))

        # Starts greyed out and un-clickable until a file type is selected
        self.save_file_button = ctk.CTkButton(self, text="Save", command=self.save_result_to_file, hover=False)
        self.save_file_button.grid(row=4, column=5, padx=(0, 10), pady=(5, 10), sticky="NSEW")
        self.save_file_button.configure(state="disabled", fg_color="#3B3B3B", require_redraw=True, cursor='')
        self.update()

    def configure_columns(self):
        """Configure how the grid columns expand when the window expands"""
        self.columnconfigure(0, weight=0)
        self.columnconfigure(1, weight=20)
        self.columnconfigure(3, weight=60)
        self.columnconfigure(4, weight=5)
        self.columnconfigure(5, weight=5)

    def configure_rows(self):
        """Configure how the grid rows expand when the window expands"""
        self.rowconfigure(0, weight=0)
        self.rowconfigure(1, weight=0)
        self.rowconfigure(2, weight=4)
        self.rowconfigure(3, weight=4)
        self.rowconfigure(4, weight=0)

    def start_thread(self, func=None):
        """Start a thread for the given func. This allows the gui to remain interactable"""
        if func is None:
            func = self.submit
        self.threads.append(threading.Thread(target=func))
        self.threads[-1].start()

    def stop_threads(self):
        """Join all running threads"""
        for thread in self.threads:
            try:
                thread.join()
            except RuntimeError:
                pass

    def submit(self):
        # Clear Output
        self.update_output_widget('')
        # Start loading bar
        self.loading_bar.set(0)
        time.sleep(0.25)
        self.loading_bar.start()

        self.results = None
        # Get list of commands from the entry field
        commands: List[str] = self.commands_entry.get("1.0", "end").strip().split("\n")

        multiprocess = SSHMultiprocess(username=self.username_entry.get().strip(),
                                       password=self.password_entry.get().strip(),
                                       hosts=self.ip_addresses_entry.get("1.0", "end").strip().split("\n"),
                                       commands=commands)

        # Start the process that sends out all the commands
        self.start_thread(multiprocess.start)
        # Wait until process is complete
        while self.results is None:
            self.results = multiprocess.results
            time.sleep(1)

        # Format the output
        text = self.format_to_text(self.results)
        print(text)
        # Display text on output widget
        self.update_output_widget(text)

        # Stop loading bar and set it to full
        self.loading_bar.stop()
        self.loading_bar.set(1)

        self.stop_threads()

    def save_result_to_file(self):
        choice = self.file_choice.get()
        # self.results = [{"Hostname": str, "Command": str, "Output": str, "Error": bool}, {...}, ]
        data = self.results

        # Remove ugly escape sequences
        for result in data:
            result["Output"] = FileHandler.remove_escape_sequences(result["Output"])

        if len(data) == 0:
            return
        try:
            FileHandler.write_to(choice, data)
        except FileHandlerException as e:
            print(f"ERROR during file handling: {e}")

    def enable_save_button(self, event, attempt=0):
        """Change the colour of the save button and allow it to be clicked"""
        # A file type must be selected and there must be data to save
        if (self.file_choice.get() != "File Type" or attempt == 1) and self.results is not None:
            self.save_file_button.configure(state="normal")
            self.save_file_button.destroy()
            self.save_file_button = ctk.CTkButton(self, text="Save", command=self.save_result_to_file)
            self.save_file_button.grid(row=4, column=5, padx=(0, 10), pady=(5, 10), sticky="NSEW")
            self.update()

        if attempt == 0 and event is not None:
            self.enable_save_button(event, 1)

    def update_output_widget(self, text):
        """Updates the output text widget to the given text"""
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", text)
        self.output_text.configure(state="disable")

    @staticmethod
    def update_entry_from_file(entry_widget):
        # Uses selects a txt file from file explorer
        data = FileHandler.open_text_file()
        # Get the text currently in the box
        current_text = entry_widget.get("1.0", "end").strip()
        # Remove all text
        entry_widget.delete("1.0", "end")
        # Display the current text plus the new text
        entry_widget.insert("1.0", f"{current_text}\n{data}".strip())

    @staticmethod
    def format_to_text(data: Iterable[Dict]) -> str:
        formatted_text = ""
        for dictionary in data:
            formatted_text += f"{dictionary.get('Hostname')}:\n{dictionary.get('Output')}\n\n"

        # Remove some of the weird escape sequence characters so that the tkinter output window accepts it nicely
        formatted_text = FileHandler.remove_escape_sequences(formatted_text)
        return formatted_text


class SSHMultiprocess:
    def __init__(self, username: str,
                 password: str,
                 hosts: List[str],
                 commands: List[str]):
        """

        :param username: Username to log into the hosts
        :param password: Password to log into the hosts
        :param hosts: List of hostnames/IP addresses
        :param commands: List of commands to run on the given host
        """
        self.username: str = username
        self.password: str = password
        self.hosts: List[str] = hosts
        self.commands: List[str] = commands
        self.compiled_command: str = self.compile_commands()
        self.queue = multiprocessing.Queue()
        self.results: None | Dict = None

    def compile_commands(self) -> str:
        """Compiles the list of commands into a single string"""
        full_command = ""
        for command in self.commands:
            if command.strip() == "":
                continue

            full_command += f"{command.strip()}\n"

        return full_command

    def create_processes(self) -> List[multiprocessing.Process]:
        """Create a list of process objects from the list of hosts"""
        # Create a list of processes
        processes = []

        # Iterate over hosts
        for host in self.hosts:
            # Ignore empty IPs
            if host.strip() == "":
                continue

            process = multiprocessing.Process(target=self.run_ssh_command, args=(host,), daemon=True)
            processes.append(process)

        return processes

    @staticmethod
    def run_processes(processes: List[multiprocessing.Process]):
        """Run the processes given and add their returns to self.queue"""
        # Start the processes
        for process in processes:
            process.start()

        # Wait for the processes to complete
        for process in processes:
            process.join()

    def run_ssh_command(self, host):
        client = paramiko.SSHClient()

        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # Prepare output
        output = {
            "Hostname": host,
            "Command": self.compiled_command,
            "Output": None,
            "Error": False,
        }
        for i in range(3):
            try:
                # Connect
                client.connect(host, username=self.username, password=self.password,
                               banner_timeout=20, timeout=20, auth_timeout=20)

                # Create shell
                channel = client.invoke_shell()
                stdin = channel.makefile('wb')
                stdout = channel.makefile('rb')

                # Run command(s)
                stdin.write(self.compiled_command)

                # Need to deepcopy to make sure data isn't lost
                output_text = copy.deepcopy(stdout.read().decode())

                # Add data to output dict
                output["Output"] = self.clean_output(output_text)

                # Flush out and close the streams
                stdout.flush()
                stdout.close()
                stdin.close()
            except paramiko.ssh_exception.NoValidConnectionsError as e:
                if i == 2:
                    print(f"Failed to SSH connect to {host}")
                    logging.error(e)
                    output["Output"] = f"Failed to connect to after three attempts"
                    output["Error"] = True
            except socket.gaierror as e:
                if i == 2:
                    print(f"Failed to find {host} after three attempts")
                    logging.error(e)
                    output["Output"] = f"Failed to find {host} after three attempts"
                    output["Error"] = True
            except TimeoutError as e:
                if i == 2:
                    print(f"Host {host} failed to respond")
                    logging.error(f"{host} failed to respond - {e}")
                    output["Output"] = f"Host failed to respond"
                    output["Error"] = True
            except paramiko.ssh_exception.AuthenticationException as e:
                if i == 2:
                    print(f"Authentication failed when connecting to {host}")
                    logging.error(e)
                    output["Output"] = f"Authentication failed"
                    output["Error"] = True
            except Exception as e:
                if i == 2:
                    print(f"An error occurred when connecting to {host} : {e}")
                    logging.error(e)
                    output["Output"] = f"An error occurred: {e}"
                    output["Error"] = True

        self.queue.put(output)
        client.close()

    def clean_output(self, output) -> str:
        """Removes any fluff that the device might return"""
        # Start from where the user is mentioned
        # Usually username@hostname#
        start = output.find(self.username)
        return output[start:]

    def start(self):
        """Create and run processes
        :return Iterable with dictionaries containing {"Hostname":str, "Command":str, "Output":str, "Error":bool}
        """
        # Create and run processes
        processes = self.create_processes()
        self.run_processes(processes)

        # Get data from queue
        output = []
        for _ in range(self.queue.qsize()):
            data: dict = self.queue.get()
            if data["Error"]:
                pass
            output.append(data)

        self.results = output


class FileHandlerException(Exception):
    pass


class FileHandler:
    """Interacting with files - formatting, reading, writing, appending etc."""

    @staticmethod
    def write_to(filetype, data):
        """Write a file to the specified type. Should be used over other direct writer methods"""
        match filetype.lower():
            case 'csv':
                FileHandler.__write_to_csv(data)
            case 'xlsx':
                FileHandler.__write_to_xlsx(data)
            case 'text':
                FileHandler.__write_to_txt(data)
            case 'sqlite':
                FileHandler.__write_to_sqlite(data)
            case _:
                raise FileHandlerException(f"Invalid file type selected - {filetype}")

    @staticmethod
    def file_explorer_save_to(file_type, file_extension) -> Path | str:
        """Open file explorer and get user to select a location and filename to save a file to."""
        path = filedialog.asksaveasfilename(title="Save File",
                                            initialdir='.',
                                            initialfile=f"SSH Tool Output{file_extension}",
                                            filetypes=file_type,
                                            defaultextension=file_extension)
        return path

    @staticmethod
    def file_explorer_open_from(filetypes: Iterable[tuple[str, str | list[str] | tuple[str, ...]]]) -> Path | str:
        """Open file explorer and get user to select a file to open."""
        path = filedialog.askopenfilename(title="Select File",
                                          initialdir='.',
                                          filetypes=filetypes, )
        return path

    @staticmethod
    def __write_to_csv(data: List[dict]):
        """Writes the given list of dictionaries to a .csv file using the first dict's keys as headers."""
        try:
            filename = FileHandler.file_explorer_save_to(file_type=[("Comma Seperated Values (*.csv)", '*.csv')],
                                                         file_extension='.csv')
            headers = data[0].keys()
            with open(filename, 'a', newline='') as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=headers)
                writer.writeheader()
                writer.writerows(data)

        except PermissionError:
            raise FileHandlerException("Cannot open file, permission denied. Make sure the file is not already open.")

    @staticmethod
    def __write_to_xlsx(data: List[dict]):
        # todo Implement
        raise FileHandlerException("xlsx formatting is yet to be implemented.")

    @staticmethod
    def __write_to_sqlite(data: List[dict]):
        # todo Implement
        raise FileHandlerException("SQLite formatting is yet to be implemented")

    @staticmethod
    def __write_to_txt(data: List[dict]):
        try:
            text = Application.format_to_text(data)
            filename = FileHandler.file_explorer_save_to(file_type=[("Text Documents (*.txt)", '*.txt')],
                                                         file_extension='.txt')
            with open(filename, 'a', newline='') as text_file:
                text_file.write(text)

        except PermissionError:
            raise FileHandlerException("Cannot open file, permission denied. Make sure the file is not already open.")

    @staticmethod
    def open_text_file() -> str:
        file_path = FileHandler.file_explorer_open_from([("Text Documents", "*.txt"), ])
        with open(file_path, 'r') as f:
            data = f.read()
        return data

    @staticmethod
    def remove_escape_sequences(text: str) -> str:
        """Remove escape sequences using re"""
        escape_seq_pattern = re.compile(r'\[\?2004[hl]|\[0m||\[01;34m')
        formatted_text = escape_seq_pattern.sub('', text)
        return formatted_text


def test_file_handler():
    data = [
        {"Hostname": '192.168.56.101',
         "Command": 'ls',
         "Output": 'Documents/',
         "Error": False},
        {"Hostname": '192.168.56.102',
         "Command": 'cd',
         "Output": 'Documents/',
         "Error": False}
    ]

    FileHandler.write_to('csv', data)


def main():
    # Allow multiprocessing to work when compiled to .exe
    multiprocessing.freeze_support()

    # Set up logger
    logging.basicConfig(filename="SSH Tool Log.log",
                        filemode='a',
                        format=f"%(levelname)s{'::':^10}%(asctime)s{'::':^10}%(message)s",
                        level=logging.DEBUG)
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # Create GUI
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    root = ctk.CTk()
    app = Application(root, log=logger)
    app.master.mainloop()


if __name__ == '__main__':
    main()
    # test_file_handler()
