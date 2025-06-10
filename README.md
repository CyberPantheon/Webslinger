# Webslinger
**Webslinger** is a custom-built, AI-integrated browser engineered from the ground up for professional bug bounty hunters, red teamers, and offensive security researchers [ comments have been made to every file and code to aid your understanding, because i built it in stacks so i can keep track of the whole codebase from "main" . 
---

## 🧠 Webslinger: The Autonomous Bug Bounty Browser

**Webslinger** is a custom-built, AI-integrated browser engineered from the ground up for professional bug bounty hunters, red teamers, and offensive security researchers. Unlike traditional browsers that passively render web content, Webslinger is an *active reconnaissance and exploitation environment* — one that thinks, crawls, and attacks with you.

At its core, Webslinger combines the flexibility of a headless-capable browser (Electron) with an embedded AI assistant (“Charlotte”), autonomous exploit engines (XSS, SQLi, recon), and full programmatic control over every browser tab and DOM surface. The result is a hacking platform that not only simulates user behavior but dynamically discovers vulnerabilities, chains payloads, and logs evidence — all in real time.

**Website** : http://webslinger.vercel.app/

**Limitations or Demo Version** :

- Lack of AI autonomy and assistance
- The AI assistant , which helps to crawl, and give codes that you can run on its terminal wont be available
- Nerfed Tools: The tools have been nerfed to minimize resources they consume
- No Admin Support

### Key Features Pro version :

- 🔍 **Autonomous XSS Spider**: Crawls every link, input, form, and reflection point to identify and test for reflected, stored, DOM-based, and blind XSS vectors.
- 💉 **Autonomous SQLi Engine**: Navigates through parameters using advanced recursive logic to detect error-based, time-based, boolean, union, and second-order SQL injections.
- 🧬 **Integrated AI Assistant (Charlotte)**: Acts as a command interpreter, security analyst, and exploit developer. It reads context from pages, helps automate attacks, explains results, and can inject JS into any tab via natural language.
- 🧠 **DevTools Execution Hook**: Any JavaScript run from the AI console is executed *directly inside the live page context*, exactly like typing into DevTools.
- 🛰️ **Network Intelligence Engine**: Tracks all fetch/XHR/WebSocket traffic, auto-documents endpoints, and maps the attack surface with full URL parameter visibility in the param hunter tool
- 🎯 **Manual + Autonomous Mode**: Jump between point-and-click interface and full AI-driven autonomous exploitation mode.
- 🗂️ **Evidence Tracker**: Automatically captures screenshots, payloads, DOM snapshots, and network traces for every successful vulnerability trigger.
- 🔍 Nmap Integration : With an intuitive GUI, you can now run nmap stright from the browser
- **Fuzzing**: You can fuzz for files, directories, files and endpoint
- **Param Hunter**: this allows you to uncover, paramaeters, both hidden and open, as well as hidden sensitive files
- **Autonomous CSRF Spider**: Allows you to hunt while it automatically craawls your targets and hunts for csrf vulnerabilities, with proper logging and reporting
- **Autonomous Open redirect spider** : Automatically crawls through your targets and hunts for open redirect opportunities , and alerts you to its findings
- **One-click proxy connection** : with a single button click, you can connect to port 8080 and let burpsuite or any of your favorite proxies intercept requests from the browser
- **Injection Tester**: Suspect an input field hidden or visible to be vulnerable to xss or sqli?, then with this tool you can spray them with payloads to confirm
- **Admin Support:** You can always contact and receive support from the creators

---
**THE FULL DOCUMENTATION OF ALL THE TOOLS CAN BE FOUND HERE :**[WEBSLINGER DOCUMENTATION on Notion](https://cyber-spac3.notion.site/WEBSLINGER-DOCUMENTATION-1f8d925480aa80fb8f6eec00cd961f70?source=copy_link)

