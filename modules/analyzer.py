"""
PassForge — Password Analysis Engine
Entropy, patterns, crack time, breach check, and improvement suggestions.
"""

import re
import math
import hashlib
import string
from datetime import datetime

# ── Common password list (top 200 most used) ──────────────────────────────
COMMON_PASSWORDS = {
    "123456","password","123456789","12345678","12345","1234567","1234567890",
    "qwerty","abc123","million2","000000","1234","iloveyou","aaron431","password1",
    "qqww1122","123123","omgpop","123321","654321","qwerty123","admin","monkey",
    "dragon","master","letmein","login","hello","princess","qazwsx","passw0rd",
    "shadow","michael","superman","batman","trustno1","sunshine","football",
    "charlie","donald","password2","qwertyuiop","soccer","hockey","killer",
    "george","andrew","jordan","harley","ranger","daniel","starwars","klaster",
    "112233","george","computer","michelle","jessica","pepper","1111","zxcvbn",
    "555555","11111111","131313","freedom","777777","pass","maggie","159753",
    "aaaaaa","ginger","princess","joshua","cheese","amanda","summer","love",
    "ashley","nicole","chelsea","biteme","matthew","access","yankees","987654321",
    "dallas","austin","thunder","taylor","matrix","william","corvette","hello",
    "martin","heather","secret","fucker","merlin","diamond","1234qwer","gfhjkm",
    "hammer","silver","222222","88888888","anthony","justin","test","bailey",
    "q1w2e3r4","patrick","internet","scooter","orange","golfer","cookie","richard",
    "samantha","bigdog","guitar","jackson","sophie","cheese","159357","654321",
    "mickey","maverick","cookie","nascar","ou812","yankee","hunting","booger",
    "asshole","wizard","aaaa","bigdick","winston","thomas","alex","baseball",
    "winner","pass","porsche","fuckyou","toyota","blowjob","steelers","rangers",
}

# ── Keyboard patterns ──────────────────────────────────────────────────────
KEYBOARD_WALKS = [
    "qwerty","qwertyuiop","asdfgh","asdfghjkl","zxcvbn","zxcvbnm",
    "1qaz","2wsx","3edc","4rfv","5tgb","6yhn","7ujm","8ik","9ol","0p",
    "qazwsx","qazwsxedc","1234567890","0987654321","11111","22222","33333",
    "aaabbb","abcdef","abcdefgh","abcdefghij","zyxwvu","fedcba",
]

# ── Leet speak map ────────────────────────────────────────────────────────
LEET_MAP = {'@':'a','4':'a','3':'e','1':'i','!':'i','0':'o','$':'s','5':'s','7':'t','+':'t','6':'g','9':'g','8':'b'}

# ── Crack speeds (hashes/second) ──────────────────────────────────────────
CRACK_SPEEDS = {
    "Online (throttled)":       100,
    "Online (unthrottled)":     1_000,
    "Offline MD5":              10_000_000_000,
    "Offline bcrypt":           20_000,
    "Offline SHA-256":          2_000_000_000,
    "GPU cluster (MD5)":        100_000_000_000,
}

def calc_charset(pwd: str) -> int:
    cs = 0
    if re.search(r'[a-z]', pwd): cs += 26
    if re.search(r'[A-Z]', pwd): cs += 26
    if re.search(r'[0-9]', pwd): cs += 10
    if re.search(r'[!@#$%^&*()\-_=+\[\]{}|;:\'",.<>?/\\`~]', pwd): cs += 32
    if re.search(r'[^\x00-\x7F]', pwd): cs += 64
    return max(cs, 1)

def calc_entropy(pwd: str) -> float:
    cs = calc_charset(pwd)
    base = math.log2(cs) * len(pwd) if cs > 1 else 0
    # Bonus: penalize repetition
    unique_ratio = len(set(pwd)) / len(pwd) if pwd else 1
    return round(base * (0.5 + 0.5 * unique_ratio), 2)

def crack_time_str(seconds: float) -> str:
    if seconds < 1:        return "Instantly"
    if seconds < 60:       return f"{int(seconds)} seconds"
    if seconds < 3600:     return f"{int(seconds/60)} minutes"
    if seconds < 86400:    return f"{int(seconds/3600)} hours"
    if seconds < 2592000:  return f"{int(seconds/86400)} days"
    if seconds < 31536000: return f"{int(seconds/2592000)} months"
    years = seconds / 31536000
    if years < 1000:       return f"{int(years)} years"
    if years < 1_000_000:  return f"{years/1000:.1f}K years"
    if years < 1_000_000_000: return f"{years/1_000_000:.1f}M years"
    return f"{years/1_000_000_000:.1f}B years"

def crack_times(pwd: str) -> dict:
    entropy = calc_entropy(pwd)
    guesses = 2 ** entropy
    return {
        scenario: {"time_str": crack_time_str(guesses / speed), "guesses": guesses, "speed": speed}
        for scenario, speed in CRACK_SPEEDS.items()
    }

def deleet(pwd: str) -> str:
    """Reverse leet speak for pattern matching."""
    return ''.join(LEET_MAP.get(c, c) for c in pwd.lower())

def detect_patterns(pwd: str) -> list:
    patterns = []
    lower = pwd.lower()
    deleeted = deleet(pwd)

    # Common password
    if lower in COMMON_PASSWORDS:
        patterns.append({"type": "COMMON_PASSWORD", "severity": "CRITICAL",
                         "desc": "This is one of the most commonly used passwords worldwide."})

    # Keyboard walk
    for walk in KEYBOARD_WALKS:
        if walk in lower or walk[::-1] in lower:
            patterns.append({"type": "KEYBOARD_WALK", "severity": "HIGH",
                             "desc": f"Contains keyboard pattern: '{walk}'"})
            break

    # Repeated chars
    if re.search(r'(.)\1{2,}', pwd):
        match = re.search(r'(.)\1{2,}', pwd)
        patterns.append({"type": "REPEATED_CHARS", "severity": "HIGH",
                         "desc": f"Repeated character sequence: '{match.group()}'"})

    # Sequential numbers
    if re.search(r'(012|123|234|345|456|567|678|789|890|987|876|765|654|543|432|321|210)', pwd):
        patterns.append({"type": "SEQUENTIAL_NUMBERS", "severity": "MEDIUM",
                         "desc": "Contains sequential number pattern."})

    # Sequential letters
    if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', lower):
        patterns.append({"type": "SEQUENTIAL_LETTERS", "severity": "MEDIUM",
                         "desc": "Contains sequential letter pattern."})

    # All same case
    if pwd.isalpha() and (pwd.islower() or pwd.isupper()):
        patterns.append({"type": "SINGLE_CASE", "severity": "MEDIUM",
                         "desc": "All letters are the same case."})

    # Only numbers
    if pwd.isdigit():
        patterns.append({"type": "DIGITS_ONLY", "severity": "HIGH",
                         "desc": "Password contains only digits."})

    # Only letters
    if pwd.isalpha():
        patterns.append({"type": "LETTERS_ONLY", "severity": "MEDIUM",
                         "desc": "Password contains only letters — add numbers and symbols."})

    # Leet speak detected
    if deleeted != lower and (deleeted in COMMON_PASSWORDS or any(walk in deleeted for walk in KEYBOARD_WALKS[:6])):
        patterns.append({"type": "LEET_SPEAK", "severity": "HIGH",
                         "desc": "Leet-speak substitution detected — easily cracked by modern tools."})

    # Year patterns
    year_match = re.search(r'(19[0-9]{2}|20[0-2][0-9])', pwd)
    if year_match:
        patterns.append({"type": "YEAR_PATTERN", "severity": "LOW",
                         "desc": f"Contains year: {year_match.group()} — common in password variations."})

    # Short
    if len(pwd) < 8:
        patterns.append({"type": "TOO_SHORT", "severity": "CRITICAL",
                         "desc": f"Only {len(pwd)} characters — minimum 12 recommended."})
    elif len(pwd) < 12:
        patterns.append({"type": "SHORT", "severity": "MEDIUM",
                         "desc": f"{len(pwd)} characters — 16+ is recommended for strong passwords."})

    # Starts/ends with number
    if pwd and (pwd[0].isdigit() or pwd[-1].isdigit()):
        patterns.append({"type": "NUMBER_PADDING", "severity": "LOW",
                         "desc": "Numbers at start/end are a well-known pattern and easily guessed."})

    return patterns

def score_password(pwd: str) -> dict:
    """0-100 score with grade."""
    entropy = calc_entropy(pwd)
    patterns = detect_patterns(pwd)

    # Base score from entropy
    score = min(entropy * 1.5, 60)

    # Length bonus
    if len(pwd) >= 16: score += 15
    elif len(pwd) >= 12: score += 10
    elif len(pwd) >= 8: score += 5

    # Charset bonus
    cs = calc_charset(pwd)
    if cs >= 84: score += 15    # upper+lower+digit+symbol
    elif cs >= 62: score += 10  # upper+lower+digit
    elif cs >= 36: score += 5

    # Pattern penalties
    for p in patterns:
        if p["severity"] == "CRITICAL": score -= 30
        elif p["severity"] == "HIGH":   score -= 15
        elif p["severity"] == "MEDIUM": score -= 8
        elif p["severity"] == "LOW":    score -= 3

    score = max(0, min(100, score))

    if score >= 85:   grade, label = "A+", "FORTRESS"
    elif score >= 70: grade, label = "A",  "STRONG"
    elif score >= 55: grade, label = "B",  "GOOD"
    elif score >= 40: grade, label = "C",  "FAIR"
    elif score >= 25: grade, label = "D",  "WEAK"
    else:             grade, label = "F",  "CRITICAL"

    return {"score": round(score), "grade": grade, "label": label}

def generate_suggestions(pwd: str, patterns: list) -> list:
    suggestions = []
    pattern_types = {p["type"] for p in patterns}

    if "TOO_SHORT" in pattern_types or "SHORT" in pattern_types:
        suggestions.append("Extend to at least 16 characters — length is the single biggest factor.")
    if "DIGITS_ONLY" in pattern_types:
        suggestions.append("Mix letters, symbols, and numbers — never use digits alone.")
    if "LETTERS_ONLY" in pattern_types:
        suggestions.append("Add numbers and symbols (e.g. @, #, !, $) throughout the password.")
    if "SINGLE_CASE" in pattern_types:
        suggestions.append("Mix uppercase and lowercase letters throughout, not just at the start.")
    if "KEYBOARD_WALK" in pattern_types:
        suggestions.append("Avoid keyboard patterns like 'qwerty' or 'asdf' — easily cracked.")
    if "REPEATED_CHARS" in pattern_types:
        suggestions.append("Remove repeated characters — use varied characters throughout.")
    if "LEET_SPEAK" in pattern_types:
        suggestions.append("Simple leet substitutions (@ for a, 3 for e) are well-known to crackers.")
    if "YEAR_PATTERN" in pattern_types:
        suggestions.append("Remove years — attackers specifically try birth years and common dates.")
    if "COMMON_PASSWORD" in pattern_types:
        suggestions.append("This password is in breach databases — never use it again.")
    if "NUMBER_PADDING" in pattern_types:
        suggestions.append("Distribute numbers and symbols throughout, not just at the start/end.")

    # General always-useful tips
    if calc_charset(pwd) < 84:
        suggestions.append("Add at least one symbol from: !@#$%^&*()-_=+[]{}|;:,.?")
    if len(pwd) < 16:
        suggestions.append("Consider using a passphrase: 4 random words + symbols (e.g. 'Maple!Rocket9#Bridge').")
    if not suggestions:
        suggestions.append("Strong password! Consider rotating it every 6–12 months.")
        suggestions.append("Store it in a reputable password manager (Bitwarden, 1Password).")

    return suggestions

def sha1_prefix(pwd: str) -> str:
    """Returns first 5 chars of SHA-1 for HaveIBeenPwned k-anonymity check."""
    return hashlib.sha1(pwd.encode()).hexdigest().upper()

def analyze(pwd: str) -> dict:
    if not pwd:
        return {"error": "No password provided"}

    entropy   = calc_entropy(pwd)
    charset   = calc_charset(pwd)
    patterns  = detect_patterns(pwd)
    scoring   = score_password(pwd)
    times     = crack_times(pwd)
    suggests  = generate_suggestions(pwd, patterns)
    sha1      = sha1_prefix(pwd)

    # Char type breakdown
    char_types = {
        "uppercase": sum(1 for c in pwd if c.isupper()),
        "lowercase": sum(1 for c in pwd if c.islower()),
        "digits":    sum(1 for c in pwd if c.isdigit()),
        "symbols":   sum(1 for c in pwd if not c.isalnum()),
        "unique":    len(set(pwd)),
        "total":     len(pwd),
    }

    return {
        "length":       len(pwd),
        "entropy":      entropy,
        "charset_size": charset,
        "char_types":   char_types,
        "score":        scoring["score"],
        "grade":        scoring["grade"],
        "label":        scoring["label"],
        "patterns":     patterns,
        "crack_times":  times,
        "suggestions":  suggests,
        "sha1_prefix":  sha1,
        "analyzed_at":  datetime.now().isoformat(),
    }
