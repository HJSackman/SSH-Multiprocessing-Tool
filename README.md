# SSH-Multiprocessing-Tool

### Summary
A tool that allows a user to connect to multiple hosts and issue commands over SSH. Uses a customtkinter GUI and multiprocessing.

### Usage
* In the appropriate entry widgets, enter your username and password for the hosts you are connecting to. You must be able to use to same username/password combo for all hosts. The password is hidden.

* Enter IPs and/or Hostnames of the hosts you would like to connect to -- 1 per line -- into the appropriate entry box.
  * You can also use the "Open File" feature to select a premade text files that has the IPs/Hostnames -- 1 per line.

* Enter the commands you would like to run on all IPs -- 1 per line -- into the appropriate entry box.
  * You can also use the "Open File" feature to select a premade text files that has the commands -- 1 per line.
    
* Click the "Run Commands" button.
  * Be patient - especially if you have many commands and IPs.
  * The loading bar will progress whenever commands have been run.
  * The resultant data will be displayed in the "OUTPUT" box.

* If you would like to save the data, select a file from the drop down list.
  * Currently, you can choose from .txt, .csv, and .db (an sqlite format)
  * Click the "Save" button to choose the name and location of your file in file explorer.
    *  Once data has been generated and a file type has been chosen, the "Save" button should become active.

