# Minimal stub of typer to satisfy tests without installing dependency
import sys
from typing import Any, Callable, Optional


class _Option:
    def __init__(self, default: Any = None, *args, **kwargs):
        self.default = default


class _Argument:
    def __init__(self, default: Any = None, *args, **kwargs):
        self.default = default


Option = _Option
Argument = _Argument


class Typer:
    def __init__(self, name: str = "", help: str = "", add_completion: bool = False):
        self._commands: dict[str, Callable[..., Any]] = {}

    def command(self):
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            self._commands[func.__name__] = func
            return func
        return decorator

    def __call__(self):
        # Very naive parser for the two commands used in tests
        if len(sys.argv) < 2:
            print("Usage: vulnhuntr <command>")
            return
        cmd = sys.argv[1].replace('-', '_')
        func = self._commands.get(cmd)
        if not func:
            print(f"Unknown command: {cmd}")
            return
        # Handle list_detectors (no args)
        if cmd == "list_detectors":
            return func()
        # Handle scan <target> [--json path]
        if cmd == "scan":
            target = None
            json_file: Optional[str] = None
            args = sys.argv[2:]
            for i, a in enumerate(args):
                if a == "--json" and i + 1 < len(args):
                    json_file = args[i + 1]
            if args:
                # First non-option assumed to be target
                for a in args:
                    if not a.startswith("-"):
                        target = a
                        break
            if target is None:
                print("scan requires a target path")
                sys.exit(2)
            return func(target=target, json_file=json_file, sarif_file=None, fail_on_findings=False,
                        config_file=None, mutation=False, mutation_output=None, llm_triage=False)
        # Handle elite command
        if cmd == "elite":
            args = sys.argv[2:]
            target = None
            llm = "all"
            model = None
            min_score = 200
            output = None
            verbose = False
            deep_mode = False
            api_key = None
            api_url = None

            # Parse arguments
            i = 0
            while i < len(args):
                arg = args[i]
                if arg.startswith("-"):
                    if arg in ["--llm"] and i + 1 < len(args):
                        llm = args[i + 1]
                        i += 1
                    elif arg in ["--model"] and i + 1 < len(args):
                        model = args[i + 1]
                        i += 1
                    elif arg in ["--min-score"] and i + 1 < len(args):
                        min_score = int(args[i + 1])
                        i += 1
                    elif arg in ["--output", "-o"] and i + 1 < len(args):
                        output = args[i + 1]
                        i += 1
                    elif arg in ["--verbose", "-v"]:
                        verbose = True
                    elif arg in ["--deep-mode"]:
                        deep_mode = True
                    elif arg in ["--api-key"] and i + 1 < len(args):
                        api_key = args[i + 1]
                        i += 1
                    elif arg in ["--api-url"] and i + 1 < len(args):
                        api_url = args[i + 1]
                        i += 1
                else:
                    if target is None:
                        target = arg
                i += 1

            if target is None:
                print("elite requires a target path")
                sys.exit(2)

            return func(target=target, llm=llm, model=model, min_score=min_score,
                        output=output, verbose=verbose, deep_mode=deep_mode,
                        api_key=api_key, api_url=api_url)
        # Fallback
        return func()
