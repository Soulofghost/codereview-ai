import pytest
from app.engine.analyzer import analyze_code_snippet

CLEAN_CODE = '''
def calculate_fibonacci(n: int) -> int:
    """Calculates the nth Fibonacci number safely."""
    if n <= 1:
        return n
    a, b = 0, 1
    for _ in range(2, n + 1):
        a, b = b, a + b
    return b
'''

VULNERABLE_CODE = '''
import os
import pickle
import hashlib
from math import *

AWS_KEY = "AKIA1111222233334444"
DB_PASSWORD = "super_secret_password_123"

def process_user_query(cursor, user_id, raw_payload, extra_list=[]):
    # Command injection
    os.system("ping -c 1 " + user_id)

    # Insecure deserialization
    obj = pickle.loads(raw_payload)

    # Weak hash
    token = hashlib.md5(user_id.encode()).hexdigest()

    # SQL Injection
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")

    try:
        val = int(user_id)
    except:
        pass

    return obj
'''

def test_clean_code_analysis():
    res = analyze_code_snippet(CLEAN_CODE, "fib.py")
    assert res["score"] >= 90
    assert res["grade"] == "A+"
    assert res["critical_issues"] == 0

def test_vulnerable_code_detection():
    res = analyze_code_snippet(VULNERABLE_CODE, "vuln.py")
    assert res["grade"] == "F"
    assert res["critical_issues"] >= 3
    assert res["total_issues"] >= 6

    rule_ids = {iss["rule_id"] for iss in res["issues"]}

    # AWS Key
    assert "SEC-001" in rule_ids
    # Command Injection
    assert "SEC-010" in rule_ids
    # Pickle Deserialization
    assert "SEC-012" in rule_ids
    # Weak MD5 Hash
    assert "SEC-013" in rule_ids
    # SQL Injection
    assert "SEC-014" in rule_ids
    # Mutable Default Arg
    assert "BUG-001" in rule_ids
    # Bare except:
    assert "BUG-002" in rule_ids
    # Wildcard import
    assert "STY-001" in rule_ids

def test_syntax_error_handling():
    broken_code = "def incomplete_func(:"
    res = analyze_code_snippet(broken_code, "broken.py")
    assert res["critical_issues"] >= 1
    assert any(iss["rule_id"] == "SYN-001" for iss in res["issues"])
