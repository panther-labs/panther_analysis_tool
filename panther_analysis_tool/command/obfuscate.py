import hashlib
import json
import os

import yaml

# Define the path to the default patterns file.
PATTERNS_FILE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..",
    "PATTERNS",
    "default_PATTERNS.json",
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
                    f"Invalid key-value pair: {key}: {value}. "
                    f"Both should be strings."
                )

    except Exception as e:
        # If there's an error, revert to using the default patterns.
        print(
            f"Error loading or validating patterns from {patterns_file}. "
            f"Exception: {e}. Using default patterns."
        )
        with open(PATTERNS_FILE_PATH, "r") as f:
            patterns = json.load(f)

    return patterns


class Base62:
    """
    Class for Base62 obfuscation and deobfuscation.
    """

    DEFAULT_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    @classmethod
    def generate_charset(cls, key):
        """
        Generate a custom charset based on a key.

        :param key: Key for generating the charset.
        :return: Custom charset.
        """
        charset = list(cls.DEFAULT_CHARSET)
        key_hash = hashlib.sha256(key.encode()).digest()
        seed = int.from_bytes(key_hash, "little")
        return "".join(sorted(charset, key=lambda x: (x + str(seed)).encode()))

    @classmethod
    def obfuscate(cls, input_data, key=None):
        """
        Obfuscate a number or a string into Base62 format.

        :param input_data: Data to obfuscate.
        :param key: Optional key for obfuscation.
        :return: Obfuscated data.
        """
        charset = cls.generate_charset(key) if key else cls.DEFAULT_CHARSET
        if isinstance(input_data, str):
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
        charset = cls.generate_charset(key) if key else cls.DEFAULT_CHARSET
        base = len(charset)
        strlen = len(base62_string)
        num = 0

        idx = 0
        for char in base62_string:
            power = strlen - (idx + 1)
            num += charset.index(char) * (base**power)
            idx += 1

        return num.to_bytes((num.bit_length() + 7) // 8, "big").decode(
            "utf-8", "ignore"
        )


def obfuscate_recursive(data, patterns, key="ATBABERS"):
    """
    Recursively obfuscate data based on patterns.

    :param data: Data to obfuscate.
    :param patterns: Patterns to match for obfuscation.
    :param key: Key for obfuscation.
    :return: Obfuscated data.
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
    Obfuscate data in a file based on patterns.

    :param args: Arguments containing file path, patterns, and key.
    :return: Status and message.
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

    :param data: Data to deobfuscate.
    :param patterns: Patterns to match for deobfuscation.
    :param key: Key for deobfuscation.
    :return: Deobfuscated data.
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
    Deobfuscate data in a file based on patterns.

    :param args: Arguments containing file path, patterns, and key.
    :return: Status and message.
    """
    patterns = validate_patterns(args.patterns if args.patterns else PATTERNS_FILE_PATH)
    with open(args.file, "r") as f:
        data = yaml.safe_load(f)
    deobfuscated_data = deobfuscate_recursive(data, patterns, key=args.key)
    with open(args.file, "w") as f:
        yaml.dump(deobfuscated_data, f)
    return 0, "Deobfuscation completed successfully."
