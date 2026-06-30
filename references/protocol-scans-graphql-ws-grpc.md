# GraphQL / WebSocket / gRPC Protocol Scans (additive — run when stack detected)

**Trigger detection:**

```bash
rg -l "graphql|GraphQL|apollo-server|@nestjs/graphql" --glob "**/*.{js,ts,java,graphql}"
rg -l "WebSocket|@ServerEndpoint|socket\.io|ws\.|STOMP" --glob "**/*.{js,ts,java}"
rg -l "grpc|@GrpcService|protobuf|\.proto" --glob "**/*.{java,go,py,proto}"
```

Skip section if no matches — mark N/A in scan attestation.

---

## GraphQL (SAST-PROTO-GL-01…04)

| Check | rg / probe |
|-------|------------|
| Introspection enabled in prod | `rg "graphiql|playground|introspection"` |
| Depth / complexity limits | `rg "maxDepth|complexity|queryDepth"` |
| Batching abuse | curl POST `{"query":"{ __schema { types { name } } }"}` |
| Auth on resolver layer | `rg "@PreAuthorize|@RolesAllowed" resolvers/` |

```bash
curl -sS -X POST -H "Content-Type: application/json" \
  -d '{"query":"{ __typename }"}' \
  "https://[HOST]/graphql"
```

---

## WebSocket (SAST-PROTO-WS-01…03)

| Check | Action |
|-------|--------|
| Origin validation | `rg "setAllowedOrigins|checkOrigin"` |
| Auth on connect / subscribe | Read `@OnOpen`, `HandshakeInterceptor` |
| Message injection | Manual: send untrusted JSON frame if test env allows |

```bash
rg -n "WebSocket|ServerEndpoint|Handshake|STOMP" --glob "**/*.java"
```

---

## gRPC (SAST-PROTO-GRPC-01…03)

| Check | Action |
|-------|--------|
| Reflection enabled | `rg "ServerReflection|protoReflection"` |
| TLS / mTLS | `rg "usePlaintext|InsecureChannel"` |
| Auth interceptors | `rg "ServerInterceptor|Metadata.*authorization"` |

---

## Report

- FINDING → **VULN-NNN** with protocol-specific category.
- N/A → note in **Scan Attestation Summary** N/A row.
- Counts roll into extended scans — **do not** add new Appendix E rows unless using full internal matrix.
