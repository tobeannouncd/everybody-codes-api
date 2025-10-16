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
        cache_path = Path(cache_dir or Path.home() / ".everybody-codes")
        cache_path.mkdir(exist_ok=True)

        # Set up session and get user info
        self.session = requests.Session()
        self.session.cookies.set(
            "everybody-codes",
            session_cookie
            or os.getenv("EC_SESSION")
            or (cache_path / "session.txt").read_text().rstrip(),
        )
        self.session.headers["user-agent"] = (
            "github.com/tobeannouncd/everybody-codes-api"
        )
        user_info = self.session.get("https://everybody.codes/api/user/me").json()
        self.cache_dir = (
            cache_path / f"user_{user_info['id']}" / f"{event_story}_{quest:02}"
        )
        self.cache_dir.mkdir(exist_ok=True)
        self.notes_path = self.cache_dir / "notes.json"
        self.keys_path = self.cache_dir / "keys.json"
        self.seed: int = user_info["seed"]

    def __getitem__(self, part: int) -> str:
        if self.notes_path.exists():
            with open(self.notes_path) as f:
                notes = json.load(f)
        else:
            notes = {"clear": {}, "crypt": self._get_notes()}
        k = str(part)
        if k in notes["clear"]:
            return notes["clear"][k]
        encrypted = bytes.fromhex(notes["crypt"][k])
        key_bytes = self._get_key(part)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=key_bytes[:16])
        clear = unpad(cipher.decrypt(encrypted), AES.block_size).decode()
        notes["clear"][k] = clear
        with open(self.notes_path, "w") as f:
            json.dump(notes, f)
        return clear

    def _get_notes(self) -> dict[str, str]:
        url = f"https://everybody-codes.b-cdn.net/assets/{self.event_story}/{self.quest}/input/{self.seed}.json"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()

    def _get_key(self, part: int) -> bytes:
        key = None
        k = f"key{part}"
        if self.keys_path.exists():
            key = json.loads(self.keys_path.read_text()).get(k)
        if key is None:
            key = self._update_keys().get(k)
        if isinstance(key, str):
            return key.encode()
        raise ValueError(f"Invalid part: {part}")

    def _update_keys(self) -> dict[str, str]:
        url = f"https://everybody.codes/api/event/{self.event_story}/quest/{self.quest}"
        response = self.session.get(url)
        response.raise_for_status()
        self.keys_path.write_bytes(response.content)
        return response.json()

    def __iter__(self) -> Iterator[str]:
        yield self[1]
        yield self[2]
        yield self[3]

    def submit(self, part: int, answer: Any) -> None:
        # Hack to ensure that integer answers are submitted properly
        if isinstance(answer, float) and answer.is_integer():
            answer = int(answer)

        keys = {}
        if self.keys_path.exists():
            keys.update(json.loads(self.keys_path.read_text()))
        k = f"answer{part}"
        if k not in keys:
            keys = self._update_keys()
        if k in keys:
            prev_answer = keys[k]
            if str(prev_answer) == str(answer):
                print("Correct answer!", file=sys.stderr)
            else:
                print(
                    "Incorrect answer.\n"
                    f"Expected: {prev_answer}\n"
                    f" But got: {answer}",
                    file=sys.stderr,
                )
            return
        print(f"Submitting {repr(answer)} for part {part}...", file=sys.stderr)
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

    def __enter__(self) -> "Quest":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def close(self) -> None:
        self.session.close()
