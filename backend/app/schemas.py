from pydantic import BaseModel, Field
from typing import List, Optional, Dict

class AnalyzeRequest(BaseModel):
    filename: Optional[str] = "app.py"
    repo_name: Optional[str] = "core-backend"
    language: Optional[str] = "python"
    code: str = Field(..., min_length=10)

class ReviewIssueOut(BaseModel):
    line_number: int
    severity: str
    category: str
    rule_id: str
    title: str
    description: str
    suggested_fix: Optional[str] = None

class ReviewReportOut(BaseModel):
    id: str
    repo_name: str
    filename: str
    language: str
    raw_code: str
    score: int
    grade: str
    total_issues: int
    critical_issues: int
    issues: List[ReviewIssueOut]
    created_at: str

class ReviewListItemOut(BaseModel):
    id: str
    repo_name: str
    filename: str
    language: str
    score: int
    grade: str
    total_issues: int
    critical_issues: int
    created_at: str

class ReviewSummaryOut(BaseModel):
    total_reviews: int
    avg_score: float
    critical_vulnerabilities_found: int
    grade_distribution: Dict[str, int]
    category_distribution: Dict[str, int]
