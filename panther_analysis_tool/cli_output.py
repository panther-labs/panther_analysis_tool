from typing import Any

from panther_analysis_tool.backend.client import BackendMultipartError


class BColors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

    @classmethod
    def bold(cls, text: str) -> str:
        return cls.wrap(cls.BOLD, text)

    @classmethod
    def header(cls, text: str) -> str:
        return cls.wrap(cls.HEADER, text)

    @classmethod
    def blue(cls, text: str) -> str:
        return cls.wrap(cls.OKBLUE, text)

    @classmethod
    def cyan(cls, text: str) -> str:
        return cls.wrap(cls.OKCYAN, text)

    @classmethod
    def green(cls, text: str) -> str:
        return cls.wrap(cls.OKGREEN, text)

    @classmethod
    def warning(cls, text: str) -> str:
        return cls.wrap(cls.WARNING, text)

    @classmethod
    def underline(cls, text: str) -> str:
        return cls.wrap(cls.UNDERLINE, text)

    @classmethod
    def failed(cls, text: str) -> str:
        return cls.wrap(cls.FAIL, text)

    @classmethod
    def wrap(cls, start: str, text: str) -> str:
        return f"{start}{text}{cls.ENDC}"


def print_op_success_msg(msg: Any) -> None:
    print(f"{BColors.green(msg)}")


def multipart_error_msg(result: BackendMultipartError, msg: str) -> str:
    return_str = "\n-----\n"

    if result.has_error():
        return_str += f"{BColors.bold('Error')}: {result.get_error()}\n-----\n"

    for issue in result.get_issues():
        if issue.path and issue.path != "":
            return_str += f"{BColors.bold('Path')}: {issue.path}\n"

        if issue.error_message and issue.error_message != "":
            return_str += f"{BColors.bold('Error')}: {issue.error_message}\n"

        return_str += "-----\n"

    return f"{return_str}\n{BColors.failed(msg)}"
