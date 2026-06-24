# Security Detection Patterns Reference

Quick reference for static pattern detection used by the AI Security Reviewer.

## Hardcoded Secrets (40+ Patterns)

### Cloud Provider Keys
| Pattern | Regex | Severity |
|---------|-------|----------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | Critical |
| AWS Secret Key | `aws_secret.*[=:]\s*["']?[A-Za-z0-9/+=]{40}` | Critical |
| GCP API Key | `AIza[0-9A-Za-z\-_]{35}` | High |
| Azure Storage Key | `azure.*storage.*key.*[=:].*[A-Za-z0-9+/=]{88}` | Critical |
| DigitalOcean Token | `dop_v1_[a-f0-9]{64}` | Critical |

### Authentication Tokens
| Pattern | Regex | Severity |
|---------|-------|----------|
| GitHub Token | `gh[pousr]_[A-Za-z0-9_]{36,}` | Critical |
| GitLab PAT | `glpat-[A-Za-z0-9\-_]{20,}` | Critical |
| Slack Token | `xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}` | Critical |
| Discord Bot Token | `[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}` | Critical |
| NPM Token | `npm_[A-Za-z0-9]{36}` | High |

### Payment & SaaS
| Pattern | Regex | Severity |
|---------|-------|----------|
| Stripe Live Key | `sk_live_[0-9a-zA-Z]{24,}` | Critical |
| Stripe Test Key | `sk_test_[0-9a-zA-Z]{24,}` | Medium |
| SendGrid API Key | `SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}` | Critical |
| Twilio API Key | `SK[0-9a-fA-F]{32}` | High |
| Mailgun API Key | `key-[0-9a-zA-Z]{32}` | High |

### Database Connection Strings
| Pattern | Regex | Severity |
|---------|-------|----------|
| MongoDB URI | `mongodb(\+srv)?://[^/\s]+:[^@/\s]+@` | Critical |
| PostgreSQL URI | `postgres(ql)?://[^/\s]+:[^@/\s]+@` | Critical |
| MySQL URI | `mysql://[^/\s]+:[^@/\s]+@` | Critical |
| Redis URI | `redis://[^/\s]+:[^@/\s]+@` | Critical |

### Cryptographic Keys
| Pattern | Regex | Severity |
|---------|-------|----------|
| RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` | Critical |
| OpenSSH Private Key | `-----BEGIN OPENSSH PRIVATE KEY-----` | Critical |
| EC Private Key | `-----BEGIN EC PRIVATE KEY-----` | Critical |
| PGP Private Key | `-----BEGIN PGP PRIVATE KEY BLOCK-----` | Critical |

---

## Injection Vulnerabilities

### SQL Injection Patterns
```python
# Python - Dangerous
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
query = f"DELETE FROM {table} WHERE id = {id}"

# Python - Safe
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
cursor.execute("SELECT * FROM users WHERE id = ?", [user_id])
```

```java
// Java - Dangerous
stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
String query = "SELECT * FROM users WHERE name = '" + name + "'";

// Java - Safe
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setInt(1, userId);
```

```javascript
// Node.js - Dangerous
db.query(`SELECT * FROM users WHERE id = ${userId}`);
connection.query("SELECT * FROM users WHERE name = '" + name + "'");

// Node.js - Safe
db.query("SELECT * FROM users WHERE id = ?", [userId]);
```

### Command Injection Patterns
```python
# Dangerous
os.system(f"ping {host}")
subprocess.call(cmd, shell=True)
subprocess.Popen(user_input, shell=True)
exec(user_code)
eval(user_input)

# Safe
subprocess.run(["ping", "-c", "1", host], shell=False)
```

```javascript
// Dangerous
exec(userCommand);
execSync(cmd);
child_process.exec(input);
spawn(cmd, {shell: true});

// Safe
execFile("ping", ["-c", "1", host]);
spawn("ping", ["-c", "1", host], {shell: false});
```

### XSS Patterns
```javascript
// Dangerous
element.innerHTML = userInput;
document.write(userData);
$(selector).html(untrustedData);
eval(userInput);

// React - Dangerous
<div dangerouslySetInnerHTML={{__html: userContent}} />

// Vue - Dangerous
<div v-html="userContent"></div>

// Safe
element.textContent = userInput;
$(selector).text(untrustedData);
```

### SSTI (Template Injection)
```python
# Jinja2 - Dangerous
render_template_string(user_input)
Template(user_input).render()
env.from_string(user_input)

# Safe
render_template("template.html", data=user_data)
```

---

## Server-Side Vulnerabilities

### SSRF Patterns
```python
# Dangerous
requests.get(user_url)
urllib.request.urlopen(user_provided_url)
httpx.get(url_from_user)

# Safe - Allowlist validation
if urlparse(url).hostname in ALLOWED_HOSTS:
    requests.get(url)
```

### Path Traversal
```python
# Dangerous
open(user_path)
os.path.join(base, "../" + user_input)
shutil.copy(user_file, dest)

# Safe
safe_path = os.path.realpath(os.path.join(base, user_input))
if safe_path.startswith(os.path.realpath(base)):
    open(safe_path)
```

### Insecure Deserialization
```python
# Dangerous
pickle.loads(user_data)
yaml.load(data)  # Uses unsafe Loader
marshal.loads(external_data)

# Safe
yaml.safe_load(data)
json.loads(data)  # JSON is safe
```

```java
// Dangerous
ObjectInputStream ois = new ObjectInputStream(userInput);
Object obj = ois.readObject();

// Dangerous libraries
XStream.fromXML(userData);
XMLDecoder.readObject();
```

---

## Cryptography Issues

### Weak Algorithms
```python
# Dangerous
hashlib.md5(password)
hashlib.sha1(password)
DES.new(key)
AES.new(key, AES.MODE_ECB)

# Safe
bcrypt.hashpw(password, bcrypt.gensalt())
hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
AES.new(key, AES.MODE_GCM)
```

### Insecure Random
```python
# Dangerous for security
random.randint(0, 999999)
random.choice(charset)

# Safe
secrets.token_hex(32)
secrets.randbelow(1000000)
os.urandom(32)
```

---

## Mobile Security Patterns

### Android
```java
// WebView - Dangerous
webView.getSettings().setJavaScriptEnabled(true);
webView.addJavascriptInterface(obj, "Android");
webView.loadUrl(userUrl);

// Insecure Storage - Dangerous
SharedPreferences prefs = getSharedPreferences("data", MODE_WORLD_READABLE);
Log.d(TAG, "Password: " + password);

// Network - Dangerous
trustAllCerts = new TrustManager[]{new X509TrustManager()...};
hostnameVerifier = (hostname, session) -> true;
```

### iOS
```swift
// Keychain - Dangerous
kSecAttrAccessible: kSecAttrAccessibleAlways

// ATS Disabled - Dangerous (Info.plist)
NSAllowsArbitraryLoads = true
NSExceptionAllowsInsecureHTTPLoads = true

// Logging - Dangerous
print("User password: \(password)")
NSLog("Token: %@", authToken)
```

---

## Configuration Issues

### Debug Mode
```python
# Flask - Dangerous
app.run(debug=True)
DEBUG = True

# Django - Dangerous
DEBUG = True
ALLOWED_HOSTS = ['*']
```

### Cookie Security
```python
# Dangerous
response.set_cookie('session', value)  # Missing secure flags

# Safe
response.set_cookie('session', value, secure=True, httponly=True, samesite='Strict')
```

### CORS Misconfiguration
```python
# Dangerous
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true

# With wildcard AND credentials is always dangerous
```

---

## OpenGrep-Aligned Classes (v3.7)

Patterns for Semgrep/OpenGrep `vulnerability_class` names we implement with `rg` + agent validation.

### Cookie Security (SAST-OG-04)
```javascript
// Dangerous — missing flags
res.cookie('session', token);
res.cookie('sid', val, { secure: false, httpOnly: false });

// Safe
res.cookie('session', token, { secure: true, httpOnly: true, sameSite: 'strict' });
```

### CSRF + Method Override (SAST-OG-05)
```javascript
// Dangerous — override before CSRF
app.use(methodOverride());
app.use(csrf()); // too late if order reversed

// Dangerous — state change without CSRF
router.post('/transfer', handler); // no csrf middleware
```

### Improper Encoding (SAST-OG-13)
```javascript
// Dangerous — raw user data in response
res.send('<div>' + req.query.name + '</div>');
// Template unquoted attribute: <div id={{userId}}>
```

### Cryptographic Issues — extended (SAST-OG-07)
```javascript
// Dangerous
crypto.pseudoRandomBytes(16);  // predictable
new WebSocket('ws://internal.service');  // no TLS
jwt.sign(payload, 'hardcoded-secret');
```

### Memory Issues (SAST-OG-20)
```javascript
// Dangerous
Buffer.allocUnsafe(size);
buf.readUInt32LE(offset, true);  // noAssert
new Buffer(str);  // deprecated unsafe
```

### LDAP Injection (SAST-OG-18)
```javascript
// Dangerous
client.search(`(uid=${username})`);
const filter = '(&(cn=' + userInput + ')(objectClass=*))';
```

### XML / XXE (SAST-OG-27)
```javascript
// Dangerous — express-xml2json style
xml2json(userXml, { object: true });  // no entity limits
```

### XPath Injection (SAST-OG-28)
```javascript
// Dangerous
xpath.select(`//user[name='${name}']`, doc);
```

### Dangerous Methods (SAST-OG-08)
```javascript
// Puppeteer / headless injection
await page.goto(req.query.url);
await page.evaluate(req.body.script);
```

### Mustache / template XSS (SAST-OG-06)
```javascript
// Dangerous
Mustache.escape = function() { return text; };
const html = `<div>${userInput}</div>`;
res.send(html);
```
