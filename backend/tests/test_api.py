import os
import pytest
from fastapi.testclient import TestClient

TEST_DB = "file:codereview_test?mode=memory&cache=shared"
os.environ["CODEREVIEW_DB_PATH"] = TEST_DB

from app.database import init_db, get_db_connection
from app.main import app

client = TestClient(app)

holding_conn = None

@pytest.fixture(scope="session", autouse=True)
def setup_database_session():
    global holding_conn
    holding_conn = init_db(TEST_DB)
    yield
    if holding_conn:
        holding_conn.close()

def test_health_check():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"
    assert res.json()["service"] == "CodeReview AI"

def test_code_review_lifecycle():
    # 1. Analyze vulnerable code
    insecure_code = """
import os
def run_command(cmd):
    AWS_TOKEN = "AKIA9999888877776666"
    os.system(cmd)
"""
    res1 = client.post("/api/reviews/analyze", json={
        "filename": "runner.py",
        "repo_name": "ops-scripts",
        "code": insecure_code
    })
    assert res1.status_code == 201
    d1 = res1.json()
    review_id = d1["id"]
    assert d1["score"] < 60
    assert d1["critical_issues"] >= 2
    assert len(d1["issues"]) >= 2

    # 2. Analyze clean code
    clean_code = '''
def add_numbers(a: int, b: int) -> int:
    """Adds two integers and returns the result."""
    return a + b
'''
    res2 = client.post("/api/reviews/analyze", json={
        "filename": "math_utils.py",
        "repo_name": "ops-scripts",
        "code": clean_code
    })
    assert res2.status_code == 201
    d2 = res2.json()
    assert d2["grade"] == "A+"
    assert d2["score"] >= 95

    # 3. List reviews
    list_res = client.get("/api/reviews?repo_name=ops-scripts")
    assert list_res.status_code == 200
    items = list_res.json()
    assert len(items) == 2

    # 4. Get detailed review
    detail_res = client.get(f"/api/reviews/{review_id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["id"] == review_id

    # 5. Review Summary Analytics
    summary_res = client.get("/api/analytics/review-summary")
    assert summary_res.status_code == 200
    summary = summary_res.json()
    assert summary["total_reviews"] == 2
    assert summary["critical_vulnerabilities_found"] >= 2
    assert "SECURITY" in summary["category_distribution"]

    # 6. Delete review
    del_res = client.delete(f"/api/reviews/{review_id}")
    assert del_res.status_code == 204

    # Verify deleted
    verify_del = client.get(f"/api/reviews/{review_id}")
    assert verify_del.status_code == 404
