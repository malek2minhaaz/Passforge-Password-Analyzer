"""
PassForge — Password Generator
Generates cryptographically secure passwords and passphrases.
"""

import secrets
import string
import random

WORDLIST = [
    "maple","rocket","bridge","forest","thunder","crystal","falcon","silver",
    "cobra","vortex","anchor","blaze","canyon","dagger","eclipse","ember",
    "forge","glacier","harbor","iron","jade","knight","lance","marble",
    "nova","obsidian","phantom","quartz","raven","saber","titan","ultra",
    "vapor","walrus","xenon","yellow","zenith","arctic","bolt","cipher",
    "delta","echo","flint","ghost","helix","ignite","jackal","krypton",
    "laser","matrix","nebula","orbit","pulse","quasar","radio","sphinx",
    "turbo","unison","vector","wolf","xray","yoke","zephyr","alpha",
    "bravo","chrome","dawn","eagle","frostbite","gamma","haze","inlet",
    "jarvis","kelp","lava","moss","north","ozone","peak","quest",
    "ridge","storm","tidal","ultra","vale","wind","axis","bear",
    "cliff","dust","edge","fern","grip","hive","isle","jolt",
    "keen","loop","mint","neon","onyx","pike","quad","rust",
    "slate","thorn","umber","veil","wake","oxide","yew","zinc",
    "acorn","birch","cedar","drift","elm","flare","grove","hawk",
    "ivy","juniper","kelvin","lynx","mist","nettle","oak","pine",
]

SYMBOLS = "!@#$%^&*-_=+?"

def generate_random(length=16, upper=True, lower=True, digits=True, symbols=True) -> str:
    charset = ""
    required = []
    if upper:   charset += string.ascii_uppercase;   required.append(secrets.choice(string.ascii_uppercase))
    if lower:   charset += string.ascii_lowercase;   required.append(secrets.choice(string.ascii_lowercase))
    if digits:  charset += string.digits;            required.append(secrets.choice(string.digits))
    if symbols: charset += SYMBOLS;                  required.append(secrets.choice(SYMBOLS))
    if not charset: charset = string.ascii_letters + string.digits

    # Fill rest
    rest = [secrets.choice(charset) for _ in range(length - len(required))]
    combined = required + rest
    # Shuffle using secrets-safe method
    for i in range(len(combined) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        combined[i], combined[j] = combined[j], combined[i]
    return ''.join(combined)

def generate_passphrase(words=4, separator="-", capitalize=True, append_number=True) -> str:
    chosen = [secrets.choice(WORDLIST) for _ in range(words)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    phrase = separator.join(chosen)
    if append_number:
        phrase += separator + str(secrets.randbelow(999) + 1)
    return phrase

def generate_pin(length=6) -> str:
    return ''.join([str(secrets.randbelow(10)) for _ in range(length)])

def generate_memorable(length=12) -> str:
    """Consonant-vowel alternating for pronounceable passwords."""
    consonants = "bcdfghjklmnpqrstvwxyz"
    vowels = "aeiou"
    result = []
    for i in range(length):
        if i % 2 == 0:
            result.append(secrets.choice(consonants).upper() if i == 0 else secrets.choice(consonants))
        else:
            result.append(secrets.choice(vowels))
    # Add number and symbol
    result[-2] = str(secrets.randbelow(9) + 1)
    result[-1] = secrets.choice(SYMBOLS)
    return ''.join(result)

def generate_batch(count=5, style="random", **kwargs) -> list:
    results = []
    for _ in range(count):
        if style == "random":      results.append(generate_random(**kwargs))
        elif style == "passphrase": results.append(generate_passphrase(**kwargs))
        elif style == "memorable":  results.append(generate_memorable(**kwargs))
        elif style == "pin":        results.append(generate_pin(**kwargs))
    return results
