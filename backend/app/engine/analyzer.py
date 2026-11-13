import ast
import re
from typing import List, Dict, Any, Tuple

class CodeReviewIssue:
    def __init__(self, line_number: int, severity: str, category: str, rule_id: str, title: str, description: str, suggested_fix: str = ""):
        self.line_number = line_number
        self.severity = severity  # CRITICAL, MAJOR, MINOR, INFO
        self.category = category  # SECURITY, BUG_RISK, COMPLEXITY, STYLE, DOCUMENTATION
        self.rule_id = rule_id
        self.title = title
        self.description = description
        self.suggested_fix = suggested_fix

    def to_dict(self) -> Dict[str, Any]:
        return {
            "line_number": self.line_number,
            "severity": self.severity,
            "category": self.category,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "suggested_fix": self.suggested_fix
        }

def scan_regex_secrets(code: str) -> List[CodeReviewIssue]:
    issues = []
    lines = code.split("\n")

    secret_patterns = [
        (r'AKIA[0-9A-Z]{16}', "CRITICAL", "SEC-001", "Hardcoded AWS Access Key", "AWS Access Key ID detected in source code. Rotate immediately and move to environment variables.", "os.environ.get('AWS_ACCESS_KEY_ID')"),
        (r'ghp_[a-zA-Z0-9]{36}', "CRITICAL", "SEC-002", "Hardcoded GitHub Personal Access Token", "GitHub Personal Access Token detected. Revoke token and inject via secrets manager.", "os.environ.get('GITHUB_TOKEN')"),
        (r'xox[baprs]-[0-9a-zA-Z]{10,48}', "CRITICAL", "SEC-003", "Hardcoded Slack API Token", "Slack bot or user token exposed in plaintext.", "os.environ.get('SLACK_API_TOKEN')"),
        (r'-----BEGIN (?:RSA )?PRIVATE KEY-----', "CRITICAL", "SEC-004", "Exposed Cryptographic Private Key", "Private RSA/EC cryptographic key committed in plaintext.", "Load certificate from secure file or HSM"),
        (r'\b(?:password|passwd|secret|api_key)\s*=\s*["\'](?!["\'])[a-zA-Z0-9_\-\.\$\@\#\!]{8,}["\']', "CRITICAL", "SEC-005", "Hardcoded High-Entropy Secret / Password", "Plaintext password or API key assigned directly in code.", "os.environ.get('SERVICE_SECRET')")
    ]

    for line_idx, line in enumerate(lines, 1):
        # Ignore comments
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        for pat, sev, rule_id, title, desc, fix in secret_patterns:
            if re.search(pat, line):
                issues.append(CodeReviewIssue(
                    line_number=line_idx,
                    severity=sev,
                    category="SECURITY",
                    rule_id=rule_id,
                    title=title,
                    description=desc,
                    suggested_fix=fix
                ))

    return issues

class ASTSecurityAndQualityVisitor(ast.NodeVisitor):
    def __init__(self, raw_code: str):
        self.raw_code = raw_code
        self.lines = raw_code.split("\n")
        self.issues: List[CodeReviewIssue] = []

    def visit_Call(self, node: ast.Call):
        # 1. Command Injection: os.system
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "os" and node.func.attr == "system":
                self.issues.append(CodeReviewIssue(
                    line_number=node.lineno,
                    severity="CRITICAL",
                    category="SECURITY",
                    rule_id="SEC-010",
                    title="Insecure Shell Execution (Command Injection)",
                    description="Calling os.system passes raw strings to the system shell, leading to arbitrary code execution if user input is supplied.",
                    suggested_fix="subprocess.run(['safe_executable', arg], check=True, shell=False)"
                ))

            # 2. Command Injection: subprocess with shell=True
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self.issues.append(CodeReviewIssue(
                            line_number=node.lineno,
                            severity="CRITICAL",
                            category="SECURITY",
                            rule_id="SEC-011",
                            title="Subprocess Invocation with shell=True",
                            description="subprocess invoked with shell=True bypasses argument escaping and enables remote command injection.",
                            suggested_fix="subprocess.run(['cmd', arg], shell=False)"
                        ))

            # 3. Insecure Deserialization: pickle.loads
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle" and node.func.attr in ("load", "loads"):
                self.issues.append(CodeReviewIssue(
                    line_number=node.lineno,
                    severity="CRITICAL",
                    category="SECURITY",
                    rule_id="SEC-012",
                    title="Insecure Deserialization (Unsafe Pickle)",
                    description="pickle.loads on untrusted binary data can execute arbitrary Python bytecode during unpickling.",
                    suggested_fix="json.loads(data) or safetensors for tensor payloads"
                ))

            # 4. Insecure Hash: hashlib.md5 or hashlib.sha1
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib" and node.func.attr in ("md5", "sha1"):
                self.issues.append(CodeReviewIssue(
                    line_number=node.lineno,
                    severity="MAJOR",
                    category="SECURITY",
                    rule_id="SEC-013",
                    title="Weak Cryptographic Hash Function",
                    description=f"hashlib.{node.func.attr} is collision-vulnerable and cryptographically deprecated.",
                    suggested_fix="hashlib.sha256(data) or hashlib.blake2b(data)"
                ))

            # 5. SQL Injection via string formatting in execute()
            if node.func.attr in ("execute", "raw_query"):
                if node.args:
                    first_arg = node.args[0]
                    if isinstance(first_arg, (ast.JoinedStr, ast.BinOp)):
                        self.issues.append(CodeReviewIssue(
                            line_number=node.lineno,
                            severity="CRITICAL",
                            category="SECURITY",
                            rule_id="SEC-014",
                            title="Potential SQL Injection via Formatted String",
                            description="Database execute() called with dynamic string interpolation instead of parameterized placeholders.",
                            suggested_fix="cursor.execute('SELECT * FROM tbl WHERE id = ?', (user_id,))"
                        ))

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # 1. Mutable default arguments (def foo(x=[]))
        for default in node.args.defaults:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                self.issues.append(CodeReviewIssue(
                    line_number=node.lineno,
                    severity="MAJOR",
                    category="BUG_RISK",
                    rule_id="BUG-001",
                    title="Mutable Default Argument Detected",
                    description=f"Function '{node.name}' uses a mutable default argument ({type(default).__name__}). Default objects persist across all invocations.",
                    suggested_fix=f"def {node.name}(arg=None):\n    if arg is None: arg = []"
                ))

        # 2. Cyclomatic Complexity
        complexity = 1
        for subnode in ast.walk(node):
            if isinstance(subnode, (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.With, ast.Assert)):
                complexity += 1
            elif isinstance(subnode, ast.BoolOp):
                complexity += len(subnode.values) - 1

        if complexity > 8:
            self.issues.append(CodeReviewIssue(
                line_number=node.lineno,
                severity="MAJOR",
                category="COMPLEXITY",
                rule_id="CMP-001",
                title=f"High Cyclomatic Complexity (M = {complexity})",
                description=f"Function '{node.name}' has cyclomatic complexity of {complexity} (threshold: 8). Decompose into modular helper functions.",
                suggested_fix=f"Refactor '{node.name}' by extracting independent sub-routines."
            ))

        # 3. Missing Docstring on non-trivial functions
        if not ast.get_docstring(node) and len(node.body) > 6:
            self.issues.append(CodeReviewIssue(
                line_number=node.lineno,
                severity="INFO",
                category="DOCUMENTATION",
                rule_id="DOC-001",
                title="Missing Function Docstring",
                description=f"Public function '{node.name}' lacks descriptive docstring documentation.",
                suggested_fix=f'"""Summary of {node.name}.\n\nArgs:\n    ...\nReturns:\n    ...\n"""'
            ))

        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        # Bare except:
        if node.type is None:
            self.issues.append(CodeReviewIssue(
                line_number=node.lineno,
                severity="MAJOR",
                category="BUG_RISK",
                rule_id="BUG-002",
                title="Bare 'except:' Clause",
                description="Bare 'except:' intercepts KeyboardInterrupt and SystemExit, hiding critical failure exceptions.",
                suggested_fix="except Exception as exc:  # Catch specific subclasses"
            ))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        # Wildcard import
        for alias in node.names:
            if alias.name == "*":
                self.issues.append(CodeReviewIssue(
                    line_number=node.lineno,
                    severity="MINOR",
                    category="STYLE",
                    rule_id="STY-001",
                    title="Wildcard Import Used (from module import *)",
                    description=f"Wildcard import from '{node.module}' pollutes namespace and obscures identifier origin.",
                    suggested_fix=f"from {node.module} import explicit_identifier"
                ))
        self.generic_visit(node)

def analyze_code_snippet(code: str, filename: str = "main.py") -> Dict[str, Any]:
    issues: List[CodeReviewIssue] = []

    # 1. Regex secrets scanner
    secret_issues = scan_regex_secrets(code)
    issues.extend(secret_issues)

    # 2. AST parsing & visitor analysis
    syntax_error = None
    try:
        tree = ast.parse(code, filename=filename)
        visitor = ASTSecurityAndQualityVisitor(code)
        visitor.visit(tree)
        issues.extend(visitor.issues)
    except SyntaxError as err:
        syntax_error = f"SyntaxError at line {err.lineno}: {err.msg}"
        issues.append(CodeReviewIssue(
            line_number=err.lineno or 1,
            severity="CRITICAL",
            category="BUG_RISK",
            rule_id="SYN-001",
            title="Python Syntax Error",
            description=syntax_error,
            suggested_fix="Correct syntax to allow complete AST parsing"
        ))

    # Sort issues by line number
    issues.sort(key=lambda x: x.line_number)

    # 3. Calculate Quality Score & Grade
    score = 100
    critical_count = 0
    for issue in issues:
        if issue.severity == "CRITICAL":
            score -= 25
            critical_count += 1
        elif issue.severity == "MAJOR":
            score -= 12
        elif issue.severity == "MINOR":
            score -= 5
        elif issue.severity == "INFO":
            score -= 2

    final_score = max(0, min(100, score))

    if final_score >= 90:
        grade = "A+"
    elif final_score >= 80:
        grade = "A"
    elif final_score >= 70:
        grade = "B"
    elif final_score >= 60:
        grade = "C"
    elif final_score >= 50:
        grade = "D"
    else:
        grade = "F"

    return {
        "score": final_score,
        "grade": grade,
        "total_issues": len(issues),
        "critical_issues": critical_count,
        "issues": [i.to_dict() for i in issues]
    }
