from collections.abc import Iterator
import json
import os
import requests
import sys

from contextlib import AbstractContextManager
from functools import cached_property
from pathlib import Path
from typing import Any
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


class Quest(AbstractContextManager):
    def __init__(
        self,
        event_story: int,
        quest: int,
        session_cookie: str | None = None,
        cache_dir: str | os.PathLike[str] | None = None,
    ):
        self.event_story = event_story
        self.quest = quest

        # Set up cache directory
        self.cache_dir = Path(cache_dir or Path.home() / ".everybody-codes")
        self.cache_dir.mkdir(exist_ok=True)

        # Set up session and get user info
        self.session = requests.Session()
        self.session.cookies.set(
            "everybody-codes",
            session_cookie
            or os.getenv("EC_SESSION")
            or (self.cache_dir / "session.txt").read_text().rstrip(),
        )
        self.session.headers["user-agent"] = (
            "github.com/tobeannouncd/everybody-codes-api"
        )
        user_info = self.session.get("https://everybody.codes/api/user/me").json()
        self.user_dir = self.cache_dir / f"user_{user_info['id']}"
        self.seed: int = user_info["seed"]

    def __getitem__(self, part: int) -> str:
        encrypted = bytes.fromhex(self._encrypted_notes[str(part)])
        key_bytes = self._keys()[f"key{part}"].encode()
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=key_bytes[:16])
        return unpad(cipher.decrypt(encrypted), AES.block_size).decode()

    def __iter__(self) -> Iterator[str]:
        yield self[1]
        yield self[2]
        yield self[3]

    def submit(self, part: int, answer: Any, display: bool = False) -> None:
        if display:
            print(f"Submitting {repr(answer)} for part {part}...", file=sys.stderr)
        keys = self._keys()
        if f"answer{part}" in keys:
            prev_answer = keys[f"answer{part}"]
            if str(prev_answer) == str(answer):
                print(
                    "This answer was already submitted and is correct.", file=sys.stderr
                )
            else:
                print(
                    f"This answer ({answer}) does not match the previous answer ({prev_answer}).",
                    file=sys.stderr,
                )
            return
        url = f"https://everybody.codes/api/event/{self.event_story}/quest/{self.quest}/part/{part}/answer"
        response = self.session.post(url, json={"answer": answer})
        response.raise_for_status()
        feedback = response.json()
        if feedback.get("correct"):
            print("Correct answer!", file=sys.stderr)
        else:
            print(
                f"Incorrect answer.\n"
                f"The length is {'' if feedback['lengthCorrect'] else 'in'}correct.\n"
                f"The first character is {'' if feedback['firstCorrect'] else 'in'}correct",
                file=sys.stderr,
            )

    @cached_property
    def _encrypted_notes(self) -> dict[str, str]:
        notes_path = self.user_dir / f"{self.event_story}-{self.quest:02}_notes.json"
        if notes_path.exists():
            with open(notes_path) as f:
                notes = json.load(f)
        else:
            url = f"https://everybody-codes.b-cdn.net/assets/{self.event_story}/{self.quest}/input/{self.seed}.json"
            response = self.session.get(url)
            response.raise_for_status()
            notes_path.write_bytes(response.content)
            notes = response.json()
        return notes

    def _keys(self) -> dict[str, str]:
        """We don't cache this because the endpoint is not static."""
        url = f"https://everybody.codes/api/event/{self.event_story}/quest/{self.quest}"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()

    def __enter__(self) -> "Quest":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def close(self) -> None:
        self.session.close()
