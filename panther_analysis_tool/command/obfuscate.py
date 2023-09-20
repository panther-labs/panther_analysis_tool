import hashlib
import json
import os
import random

import yaml


# Define the path to the default patterns file.
def find_project_root():
    """Find the project root directory."""
    marker = "panther_analysis_tool"
    current_path = os.path.abspath(__file__)  # Get the absolute path of the current file

    # If current_path is a file, get its directory
    if os.path.isfile(current_path):
        current_path = os.path.dirname(current_path)

    while current_path != os.path.dirname(current_path):  # Check until we reach the root directory
        if marker in os.listdir(current_path):
            return current_path
        current_path = os.path.dirname(current_path)
    return None


# Find the project root directory.
project_root = find_project_root()

# Define the path to the default patterns file.
PATTERNS_FILE_PATH = os.path.join(
    project_root, "panther_analysis_tool", "patterns", "default_PATTERNS.json"
)


def validate_patterns(patterns_file):
    """
    Validate the provided patterns file.

    :param patterns_file: Path to the patterns file.
    :return: Loaded patterns if valid, otherwise default patterns.
    """
    try:
        # Attempt to load the patterns from the provided file.
        with open(patterns_file, "r") as f:
            patterns = json.load(f)

        # Ensure the loaded JSON is a dictionary.
        if not isinstance(patterns, dict):
            raise ValueError("Patterns file does not contain a dictionary.")

        # Ensure all keys and values are strings.
        for key, value in patterns.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ValueError(
                    f"Invalid key-value pair: {key}: {value}. " f"Both should be strings."
                )

    except FileNotFoundError:
        # If the file is not found, use the default patterns.
        print(f"Patterns file not found: {patterns_file}. Using default patterns.")
        with open(PATTERNS_FILE_PATH, "r") as f:
            patterns = json.load(f)

    except Exception as e:
        # If there's any other error, revert to using the default patterns.
        print(
            f"Error loading or validating patterns from {patterns_file}. "
            f"Exception: {e}. Using default patterns."
        )
        with open(PATTERNS_FILE_PATH, "r") as f:
            patterns = json.load(f)

    return patterns


class Base62:
    DEFAULT_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    @classmethod
    def generate_charset(cls, key):
        """
        Generate a random character set based on a key.

        :param key: Key used to seed the random character set.
        :return: Generated character set.
        """
        charset = list(cls.DEFAULT_CHARSET)
        key_hash = hashlib.sha256(key.encode()).digest()
        seed = int.from_bytes(key_hash, "little")
        random.seed(seed)
        random.shuffle(charset)
        return "".join(charset)

    @classmethod
    def obfuscate(cls, input_data, key=None):
        """
        Obfuscate input data using Base62 encoding.

        :param input_data: Input data to obfuscate.
        :param key: Optional key for character set generation.
        :return: Obfuscated data as a Base62 string.
        """
        charset = cls.generate_charset(key) if key else cls.DEFAULT_CHARSET
        if isinstance(input_data, int):
            input_data = str(input_data).encode("utf-8")
        elif isinstance(input_data, str):
            input_data = input_data.encode("utf-8")

        num = int.from_bytes(input_data, "big")
        if num == 0:
            return charset[0]
        arr = []
        while num:
            num, rem = divmod(num, 62)
            arr.append(charset[rem])
        arr.reverse()
        return "".join(arr)

    @classmethod
    def deobfuscate(cls, base62_string, key=None):
        """
        Deobfuscate a Base62 string into a number or a string.

        :param base62_string: Base62 encoded string.
        :param key: Optional key for deobfuscation.
        :return: Deobfuscated data.
        """
        if not isinstance(base62_string, str):
            raise ValueError("Input must be a string")

        charset = cls.generate_charset(key) if key else cls.DEFAULT_CHARSET
        base = len(charset)
        strlen = len(base62_string)
        num = 0

        idx = 0
        for char in base62_string:
            if char not in charset:
                raise ValueError(f"Invalid character '{char}' in input")
            power = strlen - (idx + 1)
            num += charset.index(char) * (base**power)
            idx += 1

        return num.to_bytes((num.bit_length() + 7) // 8, "big").decode("utf-8", "ignore")


def obfuscate_recursive(data, patterns, key="ATBABERS"):
    """
    Recursively obfuscate data based on patterns.

    Args:
        data (Union[dict, list]): Data to obfuscate.
        patterns (dict): Obfuscation patterns.
        key (str, optional): Key for obfuscation. Defaults to "ATBABERS".

    Returns:
        Union[dict, list]: Obfuscated data.
    """
    if isinstance(data, dict):
        for k, value in data.items():
            if k in patterns:
                data[k] = Base62.obfuscate(value, key)
            else:
                obfuscate_recursive(value, patterns, key)
    elif isinstance(data, list):
        for index, value in enumerate(data):
            obfuscate_recursive(value, patterns, key)
    return data


def obfuscate_data(args):
    """
    Obfuscate data in a YAML file.

    Args:
        args: Command line arguments.

    Returns:
        tuple: Status code and message.
    """
    patterns = validate_patterns(args.patterns if args.patterns else PATTERNS_FILE_PATH)
    with open(args.file, "r") as f:
        data = yaml.safe_load(f)
    obfuscated_data = obfuscate_recursive(data, patterns, key=args.key)
    with open(args.file, "w") as f:
        yaml.dump(obfuscated_data, f)
    return 0, "Obfuscation completed successfully."


def deobfuscate_recursive(data, patterns, key="ATBABERS"):
    """
    Recursively deobfuscate data based on patterns.

    Args:
        data (Union[dict, list]): Data to deobfuscate.
        patterns (dict): Deobfuscation patterns.
        key (str, optional): Key for deobfuscation. Defaults to "ATBABERS".

    Returns:
        Union[dict, list]: Deobfuscated data.
    """
    if isinstance(data, dict):
        for k, value in data.items():
            if k in patterns:
                data[k] = Base62.deobfuscate(value, key)
            else:
                deobfuscate_recursive(value, patterns, key)
    elif isinstance(data, list):
        for index, value in enumerate(data):
            deobfuscate_recursive(value, patterns, key)
    return data


def deobfuscate_data(args):
    """
    Deobfuscate data in a YAML file.

    Args:
        args: Command line arguments.

    Returns:
        tuple: Status code and message.
    """
    patterns = validate_patterns(args.patterns if args.patterns else PATTERNS_FILE_PATH)
    with open(args.file, "r") as f:
        data = yaml.safe_load(f)
    deobfuscated_data = deobfuscate_recursive(data, patterns, key=args.key)
    with open(args.file, "w") as f:
        yaml.dump(deobfuscated_data, f)
    return 0, "Deobfuscation completed successfully."
