"""Built-in knowledge base: plain-language explanations keyed by CWE id.

This is the deterministic, always-available "analysis" layer. The text is written as general
reference guidance (in the spirit of OWASP/CWE descriptions) and is always worded as a possibility
until a tester confirms the finding.
"""

KB = {
    "79": {
        "name": "Cross-Site Scripting (XSS)",
        "explain": "User-controlled input may be placed into a page without proper encoding, which can let script code run in another user's browser.",
        "impact": "If confirmed exploitable, an attacker could steal session data, act as the victim, or change what the victim sees.",
        "fix": "Encode output for the context it appears in (HTML, attribute, JavaScript, URL), validate input on the server, and add a Content-Security-Policy as defence in depth.",
    },
    "89": {
        "name": "SQL Injection",
        "explain": "User input may be used inside a database query without being kept separate from the query itself, so crafted input could change what the query does.",
        "impact": "If confirmed, it could expose, change or delete database records such as credentials and personal data.",
        "fix": "Use parameterized queries or prepared statements everywhere, give the application a least-privilege database account, and validate input types.",
    },
    "22": {
        "name": "Path Traversal",
        "explain": "File paths built from user input may let someone reach files outside the folder the application intends to serve.",
        "impact": "Could expose configuration files, source code or secrets if confirmed.",
        "fix": "Never build file paths from raw input. Map requests to an allow-list of files, canonicalize paths, and reject anything outside the base directory.",
    },
    "200": {
        "name": "Information Exposure",
        "explain": "The application reveals information that users do not need, such as internal details, software versions or data.",
        "impact": "Gives attackers reconnaissance details that make other attacks easier, and may leak sensitive data directly.",
        "fix": "Remove or restrict unnecessary data in responses, comments and headers, and apply access control to sensitive endpoints.",
    },
    "209": {
        "name": "Error Message Exposure",
        "explain": "Error responses include internal details such as stack traces, file paths or database messages.",
        "impact": "Helps attackers learn how the application is built, which can speed up targeted attacks.",
        "fix": "Return generic error messages to users, log details on the server only, and disable debug mode in production.",
    },
    "284": {
        "name": "Improper Access Control",
        "explain": "Some functions or data may be reachable without a proper authorization check.",
        "impact": "If confirmed, users might view or change data that belongs to others, or reach admin features.",
        "fix": "Enforce authorization on the server for every request, deny by default, and test access rules for each user role.",
    },
    "352": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "explain": "A forged request from another website might be accepted because the application cannot tell it apart from a real user action.",
        "impact": "An attacker could trick a logged-in user into performing unwanted actions, if confirmed.",
        "fix": "Use anti-CSRF tokens on state-changing requests, set SameSite on session cookies, and check the Origin header.",
    },
    "693": {
        "name": "Missing or Weak Browser Protection (security headers)",
        "explain": "A browser security protection, usually a response header such as Content-Security-Policy or X-Content-Type-Options, is missing or weak.",
        "impact": "Weakens defence against attacks such as XSS, clickjacking and content sniffing. On its own the impact is usually low.",
        "fix": "Add the recommended security headers at the web server or application layer, then test that pages still work.",
    },
    "1021": {
        "name": "Clickjacking",
        "explain": "The page can be shown inside a frame on another website, which could be used to trick users into clicking hidden elements.",
        "impact": "Users could be tricked into unintended actions if confirmed.",
        "fix": "Send a Content-Security-Policy frame-ancestors directive (or X-Frame-Options) to control which sites may embed the page.",
    },
    "16": {
        "name": "Configuration Weakness",
        "explain": "A server or application setting may be weaker than recommended.",
        "impact": "Depends on the setting. It often gives attackers extra information or weaker protection.",
        "fix": "Compare the setting named in the finding with the vendor's hardening guidance and apply the recommended value.",
    },
    "614": {
        "name": "Cookie Without Secure Attribute",
        "explain": "A cookie may be sent over unencrypted connections because it lacks the Secure attribute.",
        "impact": "Cookie data could be exposed to someone watching network traffic.",
        "fix": "Set the Secure attribute on cookies and serve the whole site over HTTPS.",
    },
    "1004": {
        "name": "Cookie Without HttpOnly Attribute",
        "explain": "A cookie can be read by scripts in the page because it lacks the HttpOnly attribute.",
        "impact": "If a script injection issue also exists, the cookie could be read and stolen.",
        "fix": "Set HttpOnly on session cookies and any cookie that scripts do not need to read.",
    },
    "1275": {
        "name": "Cookie Without SameSite Attribute",
        "explain": "A cookie has no SameSite attribute, so the browser may send it on cross-site requests.",
        "impact": "This can make cross-site request attacks easier.",
        "fix": "Set SameSite=Lax or Strict on cookies unless cross-site use is genuinely required.",
    },
    "829": {
        "name": "Third-Party Content Without Integrity Check",
        "explain": "A page loads script or style files from another origin without a Subresource Integrity check.",
        "impact": "If that external source were compromised, malicious code could run on your pages.",
        "fix": "Add the integrity attribute (Subresource Integrity) to third-party files, or host those files yourself.",
    },
    "548": {
        "name": "Directory Listing",
        "explain": "The server may show a list of files in a folder to anyone who asks.",
        "impact": "Can reveal backup files, source code or sensitive documents.",
        "fix": "Disable directory listing on the web server and remove files that should not be public.",
    },
    "319": {
        "name": "Missing Transport Encryption",
        "explain": "Data may travel between the browser and the server without full HTTPS protection.",
        "impact": "Someone on the network path could read or change the traffic.",
        "fix": "Serve everything over HTTPS, redirect HTTP to HTTPS, and send a Strict-Transport-Security header.",
    },
    "497": {
        "name": "System Information Exposure",
        "explain": "The application reveals details about the system, such as software versions or file paths.",
        "impact": "Helps attackers match known weaknesses to your software.",
        "fix": "Hide version banners and internal paths in responses and keep software up to date.",
    },
}

# Used when a finding has no usable CWE id: match on words in the finding title.
TITLE_HINTS = [
    ("content security policy", "693"),
    ("x-content-type-options", "693"),
    ("anti-clickjacking", "1021"),
    ("x-frame-options", "1021"),
    ("strict-transport-security", "319"),
    ("httponly", "1004"),
    ("samesite", "1275"),
    ("secure flag", "614"),
    ("cross-domain javascript", "829"),
    ("sub resource integrity", "829"),
    ("subresource integrity", "829"),
    ("directory browsing", "548"),
    ("sql injection", "89"),
    ("cross site scripting", "79"),
    ("server leaks", "497"),
    ("information disclosure", "200"),
]


def lookup(cwe: str, title: str):
    """Return the KB entry for a CWE id (or a title hint), or None."""
    cwe = str(cwe or "").strip()
    if cwe in KB:
        return KB[cwe]
    lowered = (title or "").lower()
    for hint, key in TITLE_HINTS:
        if hint in lowered:
            return KB[key]
    return None
