import uuid
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query

from app.database import get_db_connection
from app.schemas import (
    AnalyzeRequest,
    ReviewReportOut,
    ReviewListItemOut,
    ReviewIssueOut,
    ReviewSummaryOut
)
from app.engine.analyzer import analyze_code_snippet

router = APIRouter(prefix="/api", tags=["code-reviews"])

@router.post("/reviews/analyze", response_model=ReviewReportOut, status_code=201)
def analyze_code(payload: AnalyzeRequest):
    analysis = analyze_code_snippet(payload.code, filename=payload.filename or "app.py")

    review_id = str(uuid.uuid4())
    conn = get_db_connection()

    with conn:
        conn.execute("""
            INSERT INTO reviews (id, repo_name, filename, language, raw_code, score, grade, total_issues, critical_issues)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            review_id,
            payload.repo_name or "local-repo",
            payload.filename or "app.py",
            payload.language or "python",
            payload.code,
            analysis["score"],
            analysis["grade"],
            analysis["total_issues"],
            analysis["critical_issues"]
        ))

        for iss in analysis["issues"]:
            iss_id = str(uuid.uuid4())
            conn.execute("""
                INSERT INTO review_issues (id, review_id, line_number, severity, category, rule_id, title, description, suggested_fix)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                iss_id, review_id, iss["line_number"], iss["severity"], iss["category"],
                iss["rule_id"], iss["title"], iss["description"], iss["suggested_fix"]
            ))

    return get_review_detail(review_id)

@router.get("/reviews", response_model=List[ReviewListItemOut])
def list_reviews(repo_name: Optional[str] = None):
    conn = get_db_connection()
    sql = "SELECT id, repo_name, filename, language, score, grade, total_issues, critical_issues, created_at FROM reviews WHERE 1=1"
    params = []
    if repo_name:
        sql += " AND repo_name = ?"
        params.append(repo_name)
    sql += " ORDER BY created_at DESC LIMIT 50"

    rows = conn.execute(sql, params).fetchall()
    return [ReviewListItemOut(**dict(r)) for r in rows]

@router.get("/reviews/{review_id}", response_model=ReviewReportOut)
def get_review_detail(review_id: str):
    conn = get_db_connection()
    rev = conn.execute("SELECT * FROM reviews WHERE id = ?", (review_id,)).fetchone()
    if not rev:
        raise HTTPException(status_code=404, detail="Code review report not found")

    issue_rows = conn.execute("SELECT * FROM review_issues WHERE review_id = ? ORDER BY line_number ASC", (review_id,)).fetchall()

    return ReviewReportOut(
        id=rev["id"],
        repo_name=rev["repo_name"],
        filename=rev["filename"],
        language=rev["language"],
        raw_code=rev["raw_code"],
        score=rev["score"],
        grade=rev["grade"],
        total_issues=rev["total_issues"],
        critical_issues=rev["critical_issues"],
        issues=[ReviewIssueOut(**dict(r)) for r in issue_rows],
        created_at=str(rev["created_at"])
    )

@router.delete("/reviews/{review_id}", status_code=204)
def delete_review(review_id: str):
    conn = get_db_connection()
    with conn:
        res = conn.execute("DELETE FROM reviews WHERE id = ?", (review_id,))
        if res.rowcount == 0:
            raise HTTPException(status_code=404, detail="Review not found")
    return None

@router.get("/analytics/review-summary", response_model=ReviewSummaryOut)
def get_summary():
    conn = get_db_connection()
    total_revs = conn.execute("SELECT COUNT(*) FROM reviews").fetchone()[0]
    avg_score = conn.execute("SELECT AVG(score) FROM reviews").fetchone()[0] or 100.0
    crit_count = conn.execute("SELECT COUNT(*) FROM review_issues WHERE severity = 'CRITICAL'").fetchone()[0]

    grade_rows = conn.execute("SELECT grade, COUNT(*) as cnt FROM reviews GROUP BY grade").fetchall()
    grade_dist = {r["grade"]: r["cnt"] for r in grade_rows}

    cat_rows = conn.execute("SELECT category, COUNT(*) as cnt FROM review_issues GROUP BY category").fetchall()
    cat_dist = {r["category"]: r["cnt"] for r in cat_rows}

    return ReviewSummaryOut(
        total_reviews=total_revs,
        avg_score=round(avg_score, 1),
        critical_vulnerabilities_found=crit_count,
        grade_distribution=grade_dist,
        category_distribution=cat_dist
    )
