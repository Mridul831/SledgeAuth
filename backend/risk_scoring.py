from schemas import Severity

def calculate_risk_score(event_count: int, has_corroborating_login: bool, has_privileged_activity: bool) -> tuple[int, Severity]:
    """
    Calculates risk score and severity based on the agreed hackathon rubric.
    """
    score = 0
    
    # 1. Threshold met (+40)
    if event_count >= 5:
        score += 40
        
    # 2. Additional failures above threshold (+0 to +20, capped)
    if event_count > 5:
        extra = (event_count - 5) * 5  # 5 points per extra failure
        score += min(extra, 20)
        
    # 3. Corroborating successful login after failures (+20)
    if has_corroborating_login:
        score += 20
        
    # 4. Supported privileged-activity indicator (+20)
    if has_privileged_activity:
        score += 20
        
    # Clamp score to 0-100
    score = max(0, min(score, 100))
    
    # Map score bands to Severity
    if 0 <= score <= 24:
        severity = Severity.LOW
    elif 25 <= score <= 49:
        severity = Severity.MEDIUM
    elif 50 <= score <= 74:
        severity = Severity.HIGH
    else:
        severity = Severity.CRITICAL
        
    return score, severity
