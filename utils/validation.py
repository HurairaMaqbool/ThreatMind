import os

def get_min_validation_score() -> int:
    score = int(os.getenv("MIN_VALIDATION_SCORE", "70"))
    return max(0, min(100, score))
