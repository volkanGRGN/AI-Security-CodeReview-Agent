"""
Code Quality & Review Patterns
Anti-patterns, dead code, maintainability issues.
"""

CODE_QUALITY_PATTERNS = [

    # ─────────────────────────────────────────────
    # DEAD CODE & DEBUGGING ARTIFACTS
    # ─────────────────────────────────────────────
    {
        'id': 'CQ-001',
        'category': 'Code Quality: Dead Code',
        'name': 'TODO/FIXME/HACK Comment',
        'severity': 'LOW',
        'pattern': r'#.*(TODO|FIXME|HACK|XXX|BUG|BROKEN|TEMP|TEMPORARY|WTF)[:!\s]',
        'description': 'Technical debt marker in code.',
        'fix': 'Convert to GitHub/Jira issue with proper tracking. Do not leave tech debt unnamed.',
        'langs': ['.py', '.js', '.ts', '.java', '.go', '.rb', '.php', '.c', '.cpp', '.swift', '.kt'],
    },
    {
        'id': 'CQ-002',
        'category': 'Code Quality: Dead Code',
        'name': 'Commented-Out Code Block',
        'severity': 'LOW',
        'pattern': r'(#\s{0,4}(def |class |import |from |if |for |while |return )|\/{2}\s{0,4}(function |class |const |let |var |if |for ))',
        'description': 'Commented-out code left in source. Reduces readability, may contain bugs.',
        'fix': 'Delete commented-out code. Use version control (git) to recover old code if needed.',
        'langs': ['.py', '.js', '.ts', '.java', '.go', '.rb', '.php'],
    },
    {
        'id': 'CQ-003',
        'category': 'Code Quality: Dead Code',
        'name': 'Print Statement in Production Code',
        'severity': 'LOW',
        'pattern': r'^\s*(print\s*\(|console\.log\s*\(|System\.out\.println\s*\(|puts\s+|dd\s*\()',
        'description': 'Debug print statement in production code. Performance impact and info leakage.',
        'fix': 'Use structured logging with proper log levels (DEBUG, INFO, WARNING, ERROR).',
        'langs': ['.py', '.js', '.ts', '.java', '.rb', '.php'],
    },

    # ─────────────────────────────────────────────
    # ERROR HANDLING
    # ─────────────────────────────────────────────
    {
        'id': 'CQ-010',
        'category': 'Code Quality: Error Handling',
        'name': 'Bare Except Clause',
        'severity': 'MEDIUM',
        'pattern': r'except\s*:\s*$|except\s*Exception\s*:\s*\n\s*pass',
        'description': 'Bare except catches everything including KeyboardInterrupt and SystemExit. Masks bugs.',
        'fix': 'Catch specific exceptions: except ValueError as e: logger.error(e)',
        'langs': ['.py'],
    },
    {
        'id': 'CQ-011',
        'category': 'Code Quality: Error Handling',
        'name': 'Empty Catch Block',
        'severity': 'MEDIUM',
        'pattern': r'catch\s*\([^)]*\)\s*\{\s*\}|catch\s*\([^)]*\)\s*\{\s*\/\/.*\}',
        'description': 'Empty catch block silently swallows exceptions. Bugs become invisible.',
        'fix': 'Log the error at minimum: catch(e) { logger.error("Operation failed", e); throw e; }',
        'langs': ['.js', '.ts', '.java', '.cs', '.swift', '.kt'],
    },
    {
        'id': 'CQ-012',
        'category': 'Code Quality: Error Handling',
        'name': 'Unhandled Promise Rejection',
        'severity': 'MEDIUM',
        'pattern': r'(\.then\s*\([^)]*\)(?!\s*\.catch)|\basync\s+function\b(?!.*try))',
        'description': 'Promise chain without .catch() handler. Unhandled rejections crash Node.js.',
        'fix': 'Add .catch() to all promise chains or use async/await with try-catch.',
        'langs': ['.js', '.ts'],
    },
    {
        'id': 'CQ-013',
        'category': 'Code Quality: Error Handling',
        'name': 'No Input Sanitization Return Value Check',
        'severity': 'MEDIUM',
        'pattern': r'(int|float|parseInt|parseFloat|atoi)\s*\(.*request|int\s*\(.*request',
        'negative_pattern': r'(try|except|catch|ValueError|isNaN|if.*None)',
        'description': 'Type conversion of user input without error handling. Crashes on invalid input.',
        'fix': 'Wrap type conversions in try-except. Validate before converting.',
        'langs': ['.py', '.js', '.ts', '.java'],
    },

    # ─────────────────────────────────────────────
    # CODE COMPLEXITY
    # ─────────────────────────────────────────────
    {
        'id': 'CQ-020',
        'category': 'Code Quality: Complexity',
        'name': 'Deep Nesting (5+ levels)',
        'severity': 'LOW',
        'pattern': r'(\s{20,})(if|for|while|try|with)\s',
        'description': 'Deeply nested code (5+ levels). Hard to test, maintain, and reason about.',
        'fix': 'Extract into functions. Use early returns. Apply guard clauses pattern.',
        'langs': ['.py', '.js', '.ts', '.java', '.go', '.rb'],
    },
    {
        'id': 'CQ-021',
        'category': 'Code Quality: Complexity',
        'name': 'Magic Numbers',
        'severity': 'LOW',
        'pattern': r'(?<!["\'\w])((?<!\.)\b(?!0\b|1\b|2\b|-1\b|100\b)\d{2,}\b)',
        'description': 'Magic number in code without named constant. Meaning unclear, hard to change.',
        'fix': 'Extract to named constant: MAX_RETRY_COUNT = 5 or use config.',
        'langs': ['.py', '.js', '.ts', '.java', '.go'],
    },

    # ─────────────────────────────────────────────
    # SECURITY ANTI-PATTERNS
    # ─────────────────────────────────────────────
    {
        'id': 'CQ-030',
        'category': 'Code Quality: Security Anti-patterns',
        'name': 'Timing Attack in String Comparison',
        'severity': 'HIGH',
        'pattern': r'(token|secret|password|api_key)\s*==\s*\w+|if\s+\w+\s*==\s*(token|secret|password)',
        'description': 'Direct string comparison for secrets. Timing side-channel attack possible.',
        'fix': 'Use hmac.compare_digest() (Python) or crypto.timingSafeEqual() (Node.js).',
        'langs': ['.py', '.js', '.ts', '.ruby'],
    },
    {
        'id': 'CQ-031',
        'category': 'Code Quality: Security Anti-patterns',
        'name': 'Global State Mutation',
        'severity': 'MEDIUM',
        'pattern': r'^(global\s+\w+|\w+\s*=\s*\{.*\})',
        'description': 'Mutable global state. Race conditions in concurrent code. Hard to test.',
        'fix': 'Pass state as function parameters. Use dependency injection. Thread-local storage if needed.',
        'langs': ['.py', '.js', '.ts'],
    },
    {
        'id': 'CQ-032',
        'category': 'Code Quality: Security Anti-patterns',
        'name': 'Returning Sensitive Data in Error Messages',
        'severity': 'HIGH',
        'pattern': r'(raise|throw|return)\s+.*\b(password|token|secret|key|email|username)\b.*\b(error|exception|message|detail)\b',
        'description': 'Sensitive data included in error messages/exceptions.',
        'fix': 'Return generic error codes. Log sensitive details server-side only.',
        'langs': ['.py', '.js', '.ts', '.java', '.go'],
    },
    {
        'id': 'CQ-033',
        'category': 'Code Quality: Security Anti-patterns',
        'name': 'Regex Without Timeout (ReDoS)',
        'severity': 'MEDIUM',
        'pattern': r'(re\.match|re\.search|re\.findall)\s*\(["\'].*(\.\*|\.\+|\\w\+).*(\.\*|\.\+|\\w\+)',
        'description': 'Complex regex without timeout. Catastrophic backtracking on crafted input.',
        'fix': 'Use timeout parameter: re.match(pattern, input, timeout=1). Simplify complex patterns.',
        'langs': ['.py'],
    },

    # ─────────────────────────────────────────────
    # DEPENDENCY ISSUES
    # ─────────────────────────────────────────────
    {
        'id': 'CQ-040',
        'category': 'Code Quality: Dependencies',
        'name': 'Unused Import',
        'severity': 'LOW',
        'pattern': r'^import\s+\w+$',
        'description': 'Top-level import that may be unused. Increases attack surface and startup time.',
        'fix': 'Remove unused imports. Use isort and autoflake for automated cleanup.',
        'langs': ['.py'],
    },
    {
        'id': 'CQ-041',
        'category': 'Code Quality: Dependencies',
        'name': 'Deprecated Function Usage',
        'severity': 'MEDIUM',
        'pattern': r'\b(mktemp|tempnam|tmpnam|gets|strcpy|sprintf|md5|sha1_file)\s*\(',
        'description': 'Deprecated or unsafe function in use.',
        'fix': 'Replace with modern secure equivalents. Check language documentation for migration guides.',
        'langs': ['.py', '.c', '.cpp', '.php'],
    },

    # ─────────────────────────────────────────────
    # TESTING
    # ─────────────────────────────────────────────
    {
        'id': 'CQ-050',
        'category': 'Code Quality: Testing',
        'name': 'No Tests Found',
        'severity': 'MEDIUM',
        'pattern': r'(def\s+\w+|function\s+\w+)',
        'negative_pattern': r'(test_|_test|\.test\.|\.spec\.|describe\(|it\(|@Test)',
        'description': 'Code without corresponding tests. Hard to refactor safely, bugs go undetected.',
        'fix': 'Add unit tests for all public functions. Aim for >80% code coverage.',
        'langs': ['.py', '.js', '.ts'],
    },
    {
        'id': 'CQ-051',
        'category': 'Code Quality: Testing',
        'name': 'Hardcoded Test Credentials',
        'severity': 'HIGH',
        'pattern': r'(test_password|test_token|fake_key|dummy_secret)\s*=\s*["\'][^"\']+["\']',
        'description': 'Hardcoded credentials in test files. Often copied to production accidentally.',
        'fix': 'Use test fixtures, factories, or environment variables even in tests.',
        'langs': ['.py', '.js', '.ts', '.java'],
    },
]
