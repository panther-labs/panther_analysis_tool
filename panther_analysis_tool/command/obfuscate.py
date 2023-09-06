import yaml
import json
import logging
import regex as re
import os
import base64

# Construct the path to the default_PATTERNS.json file
PATTERNS_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'PATTERNS', 'default_PATTERNS.json')

# Initialize the logger
logging.basicConfig(format='%(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)
VERBOSE = False

# Load regex PATTERNS
with open(PATTERNS_FILE_PATH, "r") as f:
    PATTERNS = json.load(f)


def xor_with_key(input_string, key):
    """XORs a given string with a key."""
    return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(input_string, key * len(input_string)))


def obfuscate_string(value, key="ATBABERS"):
    """Obfuscate a string."""
    obfuscated = xor_with_key(value, key)
    # Convert to Base64 to get an alphanumeric string
    return base64.b64encode(obfuscated.encode()).decode()


def obfuscate_recursive(data, patterns=PATTERNS, key="ATBABERS"):
    if isinstance(data, dict):
        for k, value in data.items():
            if k in patterns:
                data[k] = obfuscate_string(value, key)
            else:
                obfuscate_recursive(value, patterns, key)
    elif isinstance(data, list):
        for index, value in enumerate(data):
            obfuscate_recursive(value, patterns, key)
    return data


def obfuscate_data(args):
    with open(args.file, 'r') as f:
        data = yaml.safe_load(f)
    obfuscated_data = obfuscate_recursive(data, key=args.key)
    with open(args.file, 'w') as f:
        yaml.dump(obfuscated_data, f)
    return 0, "Obfuscation completed successfully."


def deobfuscate_string(value, key="ATBABERS"):
    """Deobfuscate a string."""
    try:
        # Decode from Base64
        obfuscated = base64.b64decode(value).decode()
        return xor_with_key(obfuscated, key)
    except Exception as e:
        print(f"Error deobfuscating {value}. Exception: {e}")
        return value


def deobfuscate_recursive(data, patterns=PATTERNS, key="ATBABERS"):
    if isinstance(data, dict):
        for k, value in data.items():
            if k in patterns:
                data[k] = deobfuscate_string(value, key)
            else:
                deobfuscate_recursive(value, patterns, key)
    elif isinstance(data, list):
        for index, value in enumerate(data):
            deobfuscate_recursive(value, patterns, key)
    return data


def deobfuscate_data(args):
    with open(args.file, 'r') as f:
        data = yaml.safe_load(f)
    deobfuscated_data = deobfuscate_recursive(data, key=args.key)
    with open(args.file, 'w') as f:
        yaml.dump(deobfuscated_data, f)
    return 0, "Deobfuscation completed successfully."
