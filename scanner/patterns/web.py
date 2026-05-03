"""
Web Application Security Patterns
REST API, GraphQL, WebSocket, frontend, HTTP security.
"""

WEB_PATTERNS = [

    # ─────────────────────────────────────────────
    # API SECURITY
    # ─────────────────────────────────────────────
    {
        'id': 'WEB-001',
        'category': 'Web: API Security',
        'name': 'GraphQL Introspection Enabled in Production',
        'severity': 'MEDIUM',
        'pattern': r'(introspection\s*=\s*True|GRAPHQL_INTROSPECTION\s*=\s*True)',
        'description': 'GraphQL introspection enabled. Attackers can map your entire API schema.',
        'fix': 'Disable introspection in production: introspection=not settings.DEBUG',
        'langs': ['.py', '.js', '.ts'],
    },
    {
        'id': 'WEB-002',
        'category': 'Web: API Security',
        'name': 'GraphQL Depth Limit Missing',
        'severity': 'MEDIUM',
        'pattern': r'(graphene|graphql|strawberry)',
        'negative_pattern': r'(depth_limit|max_complexity|query_depth)',
        'description': 'GraphQL without query depth limiting. Nested query DoS attacks possible.',
        'fix': 'Use graphene-validation-depth-limit or graphql-depth-limit package.',
        'langs': ['.py', '.js', '.ts'],
    },
    {
        'id': 'WEB-003',
        'category': 'Web: API Security',
        'name': 'Mass Assignment Vulnerability',
        'severity': 'HIGH',
        'pattern': r'(\*\*request\.json\(\)|Object\.assign\(.*req\.body\)|\.update\(request\.data\))',
        'description': 'Mass assignment: user controls which model fields are updated.',
        'fix': 'Use explicit field allowlists. Never directly unpack request data into model constructors.',
        'langs': ['.py', '.js', '.ts', '.rb', '.php'],
    },
    {
        'id': 'WEB-004',
        'category': 'Web: API Security',
        'name': 'API Versioning Missing',
        'severity': 'LOW',
        'pattern': r'@app\.route\(["\']/(api)?/(?!v[0-9])',
        'description': 'API route without version prefix. Hard to deprecate old endpoints safely.',
        'fix': 'Prefix all API routes: /api/v1/, /api/v2/. Use API versioning strategy.',
        'langs': ['.py', '.js', '.ts'],
    },
    {
        'id': 'WEB-005',
        'category': 'Web: API Security',
        'name': 'Missing Pagination - DoS Risk',
        'severity': 'MEDIUM',
        'pattern': r'(\.all\(\)|\.find\(\{\}\)|SELECT \* FROM|findAll\(\))',
        'negative_pattern': r'(limit|paginate|page_size|LIMIT|slice)',
        'description': 'Database query returning all records without pagination. Memory exhaustion / DoS possible.',
        'fix': 'Always paginate: .limit(100).offset(page*100) or use cursor-based pagination.',
        'langs': ['.py', '.js', '.ts', '.java', '.go', '.rb'],
    },

    # ─────────────────────────────────────────────
    # CSRF
    # ─────────────────────────────────────────────
    {
        'id': 'WEB-010',
        'category': 'Web: CSRF',
        'name': 'CSRF Protection Disabled',
        'severity': 'HIGH',
        'pattern': r'(csrf_exempt|@csrf_exempt|csrfProtection\s*:\s*false|csurf.*disabled|CSRF_COOKIE_SECURE\s*=\s*False)',
        'description': 'CSRF protection explicitly disabled on a route or globally.',
        'fix': 'Only exempt truly stateless API endpoints using JWT auth. Re-enable CSRF for session-based routes.',
        'langs': ['.py', '.js', '.ts', '.php', '.rb'],
    },
    {
        'id': 'WEB-011',
        'category': 'Web: CSRF',
        'name': 'State-Changing GET Request',
        'severity': 'HIGH',
        'pattern': r'@app\.route\(["\'].*(delete|remove|destroy|update|edit|modify).*["\'],\s*methods\s*=\s*\[["\']GET["\']',
        'description': 'State-changing operation on GET endpoint. CSRF and cache-poisoning risk.',
        'fix': 'Use POST/PUT/DELETE for all state-changing operations. GET must be idempotent.',
        'langs': ['.py'],
    },

    # ─────────────────────────────────────────────
    # FILE UPLOAD
    # ─────────────────────────────────────────────
    {
        'id': 'WEB-020',
        'category': 'Web: File Upload',
        'name': 'Unrestricted File Upload',
        'severity': 'CRITICAL',
        'pattern': r'(request\.files|multipart|FileField|upload|file\.save)',
        'negative_pattern': r'(allowed_extensions|ALLOWED_EXTENSIONS|mimetype|content_type|file_type|whitelist)',
        'description': 'File upload without extension/MIME type validation. Malicious file execution possible.',
        'fix': 'Whitelist allowed extensions. Validate MIME type server-side. Store outside webroot. Rename files.',
        'langs': ['.py', '.js', '.ts', '.php', '.rb', '.java'],
    },
    {
        'id': 'WEB-021',
        'category': 'Web: File Upload',
        'name': 'File Stored in Webroot',
        'severity': 'HIGH',
        'pattern': r'(UPLOAD_FOLDER\s*=\s*["\'].*static|upload_path.*static|save.*static/uploads)',
        'description': 'Uploaded files stored in webroot. Uploaded scripts can be executed via HTTP.',
        'fix': 'Store uploads outside webroot. Serve through a controlled endpoint that sets Content-Disposition.',
        'langs': ['.py', '.js', '.ts', '.php'],
    },

    # ─────────────────────────────────────────────
    # WEBSOCKET SECURITY
    # ─────────────────────────────────────────────
    {
        'id': 'WEB-030',
        'category': 'Web: WebSocket',
        'name': 'WebSocket Without Auth Check',
        'severity': 'HIGH',
        'pattern': r'(on_connect|on_open|websocket\.accept\(\)|socket\.on\(["\']connect)',
        'negative_pattern': r'(authenticate|verify_token|check_auth|get_current_user|jwt)',
        'description': 'WebSocket connection accepted without authentication check.',
        'fix': 'Authenticate during WebSocket handshake using token in query param or first message.',
        'langs': ['.py', '.js', '.ts'],
    },
    {
        'id': 'WEB-031',
        'category': 'Web: WebSocket',
        'name': 'WebSocket Origin Not Validated',
        'severity': 'MEDIUM',
        'pattern': r'(websocket|socket\.io|ws\.Server)',
        'negative_pattern': r'(origin|verifyClient|allowedOrigins|check_origin)',
        'description': 'WebSocket server without origin validation. Cross-site WebSocket hijacking possible.',
        'fix': 'Validate Origin header in WebSocket upgrade request against allowlist.',
        'langs': ['.py', '.js', '.ts'],
    },

    # ─────────────────────────────────────────────
    # HTTP SECURITY HEADERS
    # ─────────────────────────────────────────────
    {
        'id': 'WEB-040',
        'category': 'Web: Security Headers',
        'name': 'Clickjacking Protection Missing',
        'severity': 'MEDIUM',
        'pattern': r'(createServer|app\.listen|fastapi\s*=\s*FastAPI)',
        'negative_pattern': r'(X-Frame-Options|frame-ancestors|helmet)',
        'description': 'No clickjacking protection. UI redressing attacks possible.',
        'fix': 'Set X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors \'none\'',
        'langs': ['.py', '.js', '.ts'],
    },
    {
        'id': 'WEB-041',
        'category': 'Web: Security Headers',
        'name': 'Content-Security-Policy Missing or Weak',
        'severity': 'MEDIUM',
        'pattern': r'(Content-Security-Policy|content_security_policy)\s*[=:]\s*["\'].*unsafe-inline.*["\']',
        'description': "CSP contains 'unsafe-inline'. XSS protection of CSP is bypassed.",
        'fix': "Remove 'unsafe-inline'. Use nonces or hashes for inline scripts instead.",
        'langs': ['.py', '.js', '.ts', '.html'],
    },
    {
        'id': 'WEB-042',
        'category': 'Web: Security Headers',
        'name': 'HSTS Not Configured',
        'severity': 'MEDIUM',
        'pattern': r'(SSL_REDIRECT|SECURE_SSL_REDIRECT|force_https)',
        'negative_pattern': r'(Strict-Transport-Security|HSTS|max-age)',
        'description': 'HTTPS redirect without HSTS header. Downgrade attacks possible on first connection.',
        'fix': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        'langs': ['.py', '.js', '.ts'],
    },

    # ─────────────────────────────────────────────
    # FRONTEND / CLIENT-SIDE
    # ─────────────────────────────────────────────
    {
        'id': 'WEB-050',
        'category': 'Web: Frontend',
        'name': 'Sensitive Data in localStorage',
        'severity': 'HIGH',
        'pattern': r'localStorage\.(setItem|getItem)\s*\(.*\b(token|password|secret|key|auth|jwt|session)\b',
        'description': 'Sensitive data stored in localStorage. Accessible to any JS, XSS exfiltrates it.',
        'fix': 'Store auth tokens in httpOnly cookies. Use sessionStorage at most for non-critical temp data.',
        'langs': ['.js', '.ts', '.jsx', '.tsx', '.html'],
    },
    {
        'id': 'WEB-051',
        'category': 'Web: Frontend',
        'name': 'postMessage Without Origin Check',
        'severity': 'HIGH',
        'pattern': r'addEventListener\s*\(["\']message["\']',
        'negative_pattern': r'(event\.origin|message\.origin|origin\s*===)',
        'description': 'postMessage listener without origin validation. Any page can send malicious messages.',
        'fix': 'Always check event.origin before processing postMessage data.',
        'langs': ['.js', '.ts', '.jsx', '.tsx', '.html'],
    },
    {
        'id': 'WEB-052',
        'category': 'Web: Frontend',
        'name': 'Client-Side Auth Only',
        'severity': 'CRITICAL',
        'pattern': r'(if\s*\(.*isAdmin|if\s*\(.*role\s*===|if\s*\(.*user\.admin)\s*\{',
        'description': 'Authorization check only on client-side. Bypassed by modifying JS in browser.',
        'fix': 'All authorization checks must be enforced server-side. Client checks are UX only.',
        'langs': ['.js', '.ts', '.jsx', '.tsx'],
    },

    # ─────────────────────────────────────────────
    # REGEX & DOS
    # ─────────────────────────────────────────────
    {
        'id': 'WEB-060',
        'category': 'Web: DoS',
        'name': 'ReDoS - Catastrophic Backtracking',
        'severity': 'MEDIUM',
        'pattern': r'new RegExp\(.*\+.*\)|re\.compile\(.*\+',
        'description': 'Regex constructed from user input. ReDoS (Regex Denial of Service) possible.',
        'fix': 'Never build regexes from user input. Use timeout-based regex or simple string matching.',
        'langs': ['.js', '.ts', '.py'],
    },
    {
        'id': 'WEB-061',
        'category': 'Web: DoS',
        'name': 'No Request Size Limit',
        'severity': 'MEDIUM',
        'pattern': r'(app = Flask|express\(\)|FastAPI\(\)|new Koa\(\))',
        'negative_pattern': r'(MAX_CONTENT_LENGTH|limit|bodyParser.*limit|max_upload_size)',
        'description': 'Web application without request body size limit. Large payload DoS possible.',
        'fix': 'Set MAX_CONTENT_LENGTH (Flask) or limit (Express): app.use(express.json({ limit: "10kb" }))',
        'langs': ['.py', '.js', '.ts'],
    },
]
