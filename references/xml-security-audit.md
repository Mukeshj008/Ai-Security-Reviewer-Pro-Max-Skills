# XML Security Audit (MANDATORY when XML/SOAP/SAML parsing or construction exists)

**Purpose:** cover both parser attacks (XXE/entity expansion) and structural XML injection. This audit is additive to language-pack L13 and runs even when an active language pack exists. `injection-deep-scan.md` remains legacy fallback only.

## 1. Build the XML surface map

Inventory every first-party location that:

- parses request bodies, uploads, queue messages, SOAP/SAML documents, SVG, office files, or third-party XML responses;
- constructs XML through concatenation, interpolation, templates, DOM builders, serializers, or XPath;
- validates XML signatures or consumes a node selected from a signed document.

For each location record:

| Source | Parser/builder | Hardening instance | Consumer/sink | Trust boundary |
|--------|----------------|--------------------|---------------|----------------|

Values read from DB/queues are attacker-controlled when a user or partner could have stored them earlier. A partner response is untrusted when TLS validation is disabled or the response lacks application-level integrity.

## 2. XXE and entity-expansion gate (XXE-ADJ-01)

Do not report merely because a parser class exists. Follow the exact parser/factory instance from construction to parse/unmarshal and verify its pinned runtime/library behavior.

### Java/JVM

For `DocumentBuilderFactory` / `SAXParserFactory`, require the parser-appropriate combination:

- DOCTYPE disallowed, **or** external general and parameter entities disabled;
- external DTD and schema access empty where supported;
- XInclude disabled;
- entity expansion disabled where supported;
- secure-processing limits enabled as defense in depth.

For `XMLInputFactory`, require `SUPPORT_DTD=false` and `IS_SUPPORTING_EXTERNAL_ENTITIES=false`. For `TransformerFactory`, `SchemaFactory`, and XSLT, also restrict external DTD/stylesheet/schema access. JAXB typed binding is not protection unless fed by a hardened `XMLStreamReader`/`SAXSource`.

**Important:** `FEATURE_SECURE_PROCESSING=true` alone is not sufficient proof of XXE prevention. It may apply resource limits without disabling all external resolution paths.

### Python

Prefer `defusedxml`. For `lxml`, verify `resolve_entities=False`, `no_network=True`, and no attacker-controlled resolver/catalog. Distinguish external entity fetch from internal entity expansion; severity and CWE may differ.

### Node/browser and other runtimes

Use the active language pack to establish parser defaults in the pinned version. `xml2js` or `fast-xml-parser` is not an XXE finding merely because it parses XML; prove DTD/entity support is enabled. Browser `DOMParser` does not fetch external entities, but parsing as HTML and inserting into DOM can become XSS.

### Verdict

- **Finding:** attacker-controlled XML reaches an entity-capable parser without complete parser-specific hardening.
- **Appendix A (G3):** exact parser instance is hardened; cite every relevant setting or secure-by-default pinned version.
- **Tentative:** parser implementation/version or factory-to-sink linkage cannot be established.

## 3. XML structural injection (XML-ADJ-01)

Trace attacker data into XML **structure**, not merely XML text.

### Vulnerable patterns

- string/template concatenation into element names, attribute names, tag delimiters, namespace declarations, processing instructions, CDATA boundaries, comments, or raw XML fragments;
- unescaped text inserted into an attribute or element (`"`, `'`, `<`, `>`, `&`);
- attacker-controlled XPath/XSLT expressions;
- "escape `<` only" or regex/blocklist sanitization;
- a builder API invoked with attacker-controlled **element/attribute name** even when values are escaped.

### Effective controls

- DOM/builder APIs with fixed element and attribute names plus `createTextNode` / `setTextContent` / serializer-escaped values;
- schema-backed serializer with fixed field names, provided raw-fragment escape hatches are not used;
- context-correct escaping for text vs attribute values;
- XPath variables/bound parameters rather than expression concatenation;
- explicit allowlist for dynamic names/namespaces.

### Required proof

Document source → propagation → construction sink → downstream parser/partner. Show the resulting structure an attacker can alter (for example add a sibling element, close an attribute, change an XPath predicate, or inject a signature-relevant node). If malformed XML is only rejected and no security boundary changes, do not report injection; consider availability only if repeatable resource exhaustion is proven.

## 4. XML signature wrapping / privilege effects

For SAML, SOAP signatures, and XML-DSig:

1. identify the node whose signature is verified;
2. identify the node later consumed for identity/role/amount/action;
3. verify they are the same unique node and ID resolution rejects duplicates;
4. verify reference URI, recipient, audience, destination, time, and replay controls.

Signature-valid-but-different-node consumption is an authentication/authorization finding, not merely generic XML injection.

## 5. Reporting

- Parser entity resolution: CWE-611 / CWE-776 as applicable.
- Structural XML injection: CWE-91 (or precise XPath/XSLT CWE where applicable).
- Signature wrapping with privilege impact: AUTH/VULN using the authentication/authorization CWE.
- Non-HTTP XML findings: Burp PoC `N/A`; HTTP/SOAP findings include a complete raw request.
- Every excluded candidate records `XXE-ADJ-01` or `XML-ADJ-01` and the failed gate.
