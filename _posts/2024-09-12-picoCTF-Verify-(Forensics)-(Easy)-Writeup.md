# Hey there!

In this writeup, I will solve the picoCTF Verify Forensics challenge.

When I open the folder, we are greeted by 3 things:

![VirtualBoxVM_B4jWX9L3IT](https://github.com/user-attachments/assets/5ecf9779-785a-4dd9-b03a-1b632f41d7de)


`checksum.txt`,`decrypt.sh` And `files`

When we look in the `decrypt.sh` file, we find the following code:

```sh

        #!/bin/bash

        # Check if the user provided a file name as an argument
        if [ $# -eq 0 ]; then
            echo "Expected usage: decrypt.sh <filename>"
            exit 1
        fi

        # Store the provided filename in a variable
        file_name="$1"

        # Check if the provided argument is a file and not a folder
        if [ ! -f "/home/ctf-player/drop-in/$file_name" ]; then
            echo "Error: '$file_name' is not a valid file. Look inside the 'files' folder with 'ls -R'!"
            exit 1
        fi

        # If there's an error reading the file, print an error message
        if ! openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -salt -in "/home/ctf-player/drop-in/$file_name" -k picoCTF; then
            echo "Error: Failed to decrypt '$file_name'. This flag is fake! Keep looking!"
        fi
```

When we look in the `checksum` file, we are greeted by the following sha512 checksum:
`3ad37ed6c5ab81d31e4c94ae611e0adf2e9e3e6bee55804ebc7f386283e366a4`

And ls'ing into the `files` folder gives us this:
![image](https://github.com/user-attachments/assets/9720ab17-6620-491b-aab9-bc6b9f661d93)

Lets Solve this.

I made a python script with the debugging help of chatGPT to make this script that iterates every file in the files folder with the 

`openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -salt -in "/home/ctf-player/drop-in/$file_name" -k picoCTF;` command as shown here:

```py
import os

def run_bash_script_on_files(folder_path, bash_script_path):
    """Runs a bash script on each file in a specified folder.

    Args:
        folder_path: The path to the folder containing the files.
        bash_script_path: The path to the bash script to run.
    """

    for file in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file)
        if os.path.isfile(file_path):
            command = f"{bash_script_path} {file_path}"
            os.system(command)

            # Check for decryption error
            if os.system(f"openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -salt -in '{file_path}' -k picoCTF") != 0:
                print(f"Error: Failed to decrypt '{file_path}'. This flag is fake! Keep looking!")
            else:
                print(f"Found! {file_path}")
                exit()

if __name__ == "__main__":
    folder_path = "./files"  # Replace with the actual folder path
    bash_script_path = "./decrypt.sh"  # Replace with the actual script path
    run_bash_script_on_files(folder_path, bash_script_path)
```
Running the script, like so, our output will look like this:

```
Error: Failed to decrypt './files/QNPhWoha'. This flag is fake! Keep looking!
Error: './files/JJxoEHaC' is not a valid file. Look inside the 'files' folder with 'ls -R'!
bad magic number
Error: Failed to decrypt './files/JJxoEHaC'. This flag is fake! Keep looking!
Error: './files/OX3IlkB9' is not a valid file. Look inside the 'files' folder with 'ls -R'!
bad magic number
Error: Failed to decrypt './files/OX3IlkB9'. This flag is fake! Keep looking!
Error: './files/dINee6RV' is not a valid file. Look inside the 'files' folder with 'ls -R'!
bad magic number
Error: Failed to decrypt './files/dINee6RV'. This flag is fake! Keep looking!
Error: './files/bIl1SDxK' is not a valid file. Look inside the 'files' folder with 'ls -R'!
bad magic number
Error: Failed to decrypt './files/bIl1SDxK'. This flag is fake! Keep looking!
Error: './files/ffw8WXYD' is not a valid file. Look inside the 'files' folder with 'ls -R'!
bad magic number
Error: Failed to decrypt './files/ffw8WXYD'. This flag is fake! Keep looking!
Error: './files/Oq8kRa6b' is not a valid file. Look inside the 'files' folder with 'ls -R'!
bad magic number
Error: Failed to decrypt './files/Oq8kRa6b'. This flag is fake! Keep looking!
Error: './files/YG1pCKDt' is not a valid file. Look inside the 'files' folder with 'ls -R'!
bad magic number
Error: Failed to decrypt './files/YG1pCKDt'. This flag is fake! Keep looking!
Error: './files/st6t5Khc' is not a valid file. Look inside the 'files' folder with 'ls -R'!
bad magic number
Error: Failed to decrypt './files/st6t5Khc'. This flag is fake! Keep looking!
Error: './files/oaOPzO00' is not a valid file. Look inside the 'files' folder with 'ls -R'!
bad magic number
Error: Failed to decrypt './files/oaOPzO00'. This flag is fake! Keep looking!
Error: './files/q2yrfUO0' is not a valid file. Look inside the 'files' folder with 'ls -R'!
bad magic number
Error: Failed to decrypt './files/q2yrfUO0'. This flag is fake! Keep looking!
Error: './files/e018b574' is not a valid file. Look inside the 'files' folder with 'ls -R'!
picoCTF{trust_but_verify_e018b574}
Found! ./files/e018b574
```

Hope you enjoyed this Writeup, See you next time!


