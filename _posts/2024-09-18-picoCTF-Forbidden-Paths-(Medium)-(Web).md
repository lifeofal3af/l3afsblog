# Hey There!
Today I will be attempting to hack the [Picoctf Forbidden Paths (Medium) ](https://play.picoctf.org/practice/challenge/270) challenge.

### Description
Can you get the flag? We know that the website files live in /usr/share/nginx/html/ and the flag is at /flag.txt but the website is filtering absolute file paths. Can you get past the filter to read the flag? Here's the website.
## Initial Reconnaissance

Upon checking out the challenge website, we get a simple page:

![Challenge homepage](https://github.com/user-attachments/assets/19185b7d-2fdb-49f7-a7ff-6a2395e469e8)

## Testing Basic Functionality

To see how the site works, we can try putting one of the files into the search bar:

![File content display](https://github.com/user-attachments/assets/4ef8fa1a-4b31-4c90-a6f3-2be5d94ebab9)

This displays the contents of the file, confirming that the site reads and returns file contents based on user input.

## Identifying the Vulnerability

Because of the challenge description and the site's behavior, we can probably say that this is likely vulnerable to Local File Inclusion (LFI). LFI allows an attacker to read files on a server through the web browser.


## Crafting the Exploit

To exploit this LFI vulnerability and read the flag, we need to construct a path that:

1. Avoids using absolute paths (to bypass the filter)
2. Navigates from the web root (`/usr/share/nginx/html/`) to the root directory (`/`)
3. Accesses the `flag.txt` file

Considering all these hurdles, I made this exploit:
```
../../../../flag.txt
```


## Executing the Exploit

When I input this path into the search bar:



Success! The server reads and returns the contents of `/flag.txt`.

## Flag

The flag is revealed to be:

```
picoCTF{7h3_p47h_70_5ucc355_e5fe3d4d}
```
Thanks for reading!
