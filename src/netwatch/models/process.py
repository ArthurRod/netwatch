import re
from dataclasses import dataclass
from pathlib import PurePosixPath

INTERPRETER_NAME = re.compile(r"^(python[\d.]*|node|nodejs|bash|sh|dash|zsh|perl[\d.]*|ruby[\d.]*|php[\d.]*|deno|bun|lua[\d.]*|osascript|pwsh)$")
INLINE_CODE_FLAGS = {"-c", "-e", "--eval", "-p", "--print"}
MODULE_FLAG = "-m"

SECRET_NAME = r"(pass(word|wd)?|token|secret|api[-_]?key|auth(orization)?|credentials?)"
SECRET_ASSIGNMENT = re.compile(rf"(?i)^(-{{0,2}}[\w.-]*{SECRET_NAME}[\w.-]*=)(.+)$")
SECRET_FLAG = re.compile(rf"(?i)^-{{1,2}}[\w.-]*{SECRET_NAME}[\w.-]*$")
URL_CREDENTIALS = re.compile(r"(://[^/\s:@]+:)[^/\s@]+@")
BEARER = re.compile(r"(?i)(bearer\s+)\S+")
REDACTED = "***"


def redact_arguments(arguments: tuple[str, ...]) -> tuple[str, ...]:
    redacted = []
    hide_next = False
    for argument in arguments:
        if hide_next:
            redacted.append(REDACTED)
            hide_next = False
            continue
        hide_next = bool(SECRET_FLAG.match(argument))
        argument = SECRET_ASSIGNMENT.sub(rf"\g<1>{REDACTED}", argument)
        argument = URL_CREDENTIALS.sub(rf"\g<1>{REDACTED}@", argument)
        argument = BEARER.sub(rf"\g<1>{REDACTED}", argument)
        redacted.append(argument)
    return tuple(redacted)


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    pid: int
    name: str
    exe: str | None
    exe_deleted: bool
    cmdline: tuple[str, ...]
    username: str | None
    ancestors: tuple[tuple[int, str], ...]
    cwd: str | None = None

    @property
    def is_interpreter(self) -> bool:
        return bool(INTERPRETER_NAME.match(self.name))

    @property
    def script(self) -> str | None:
        if not self.is_interpreter:
            return None
        arguments = iter(self.cmdline[1:])
        for argument in arguments:
            if argument == MODULE_FLAG:
                return f"-m {next(arguments, '')}".strip()
            if argument in INLINE_CODE_FLAGS:
                return argument
            if argument.startswith("-"):
                continue
            return argument
        return None

    @property
    def script_path(self) -> str | None:
        script = self.script
        if script is None or script.startswith("-"):
            return None
        path = PurePosixPath(script)
        if not path.is_absolute() and self.cwd:
            path = PurePosixPath(self.cwd) / path
        return str(path)

    @property
    def label(self) -> str:
        script = self.script
        if script is None:
            return self.name
        if script.startswith("-"):
            return f"{self.name} {script}"
        return f"{self.name} {PurePosixPath(script).name}"

    @property
    def group_key(self) -> str:
        return f"{self.exe or self.name}\0{self.script or ''}"

    @property
    def command(self) -> str:
        return " ".join(self.cmdline) if self.cmdline else self.name

    @property
    def lineage(self) -> str:
        return " ← ".join(f"{name} ({pid})" for pid, name in self.ancestors)
