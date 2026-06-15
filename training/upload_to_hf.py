#!/usr/bin/env python3
"""Push the burpwn fine-tuning dataset (files + card) to a Hugging Face dataset repo.

This uploads the generated JSONL files and the README dataset card to a HF
*dataset* repository. It NEVER hardcodes a token: the token is read from
``--token``, then ``$HF_TOKEN`` / ``$HUGGING_FACE_HUB_TOKEN``, then the cached
login (``huggingface-cli login`` / ``hf auth login``). If none is found it prints
clear instructions and exits without uploading.

Usage::

    # 1. authenticate once (any of):
    huggingface-cli login            # or: hf auth login
    export HF_TOKEN=hf_xxx

    # 2. (re)generate the dataset files
    python generate.py

    # 3. push (dry-run first to see what would happen)
    python upload_to_hf.py --dry-run
    python upload_to_hf.py                          # → own2pwn-fr/burpwn-usage
    python upload_to_hf.py --repo myorg/burpwn-usage --private

Files uploaded (when present): dataset.jsonl, dataset.train.jsonl,
dataset.validation.jsonl, README.md (the dataset card).
"""

from __future__ import annotations

import argparse
import os
import sys

DEFAULT_REPO = os.environ.get("BURPWN_HF_REPO", "own2pwn-fr/burpwn-usage")
HERE = os.path.dirname(os.path.abspath(__file__))

# Files we publish, in a sensible order. Missing files are skipped with a note.
DATASET_FILES = [
    "dataset.jsonl",
    "dataset.train.jsonl",
    "dataset.validation.jsonl",
    "README.md",
    "generate.py",  # ship the source-of-truth generator for reproducibility
]


def _resolve_token(explicit: str | None) -> str | None:
    if explicit:
        return explicit
    for var in ("HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HUGGINGFACE_TOKEN"):
        if os.environ.get(var):
            return os.environ[var]
    # Fall back to a cached login, if any. huggingface_hub >= 1.0 exposes
    # `get_token()`; older versions only had `HfFolder.get_token()`. Try both so
    # the cached `hf auth login` / `huggingface-cli login` token is picked up
    # across hub versions.
    try:
        from huggingface_hub import get_token

        tok = get_token()
        if tok:
            return tok
    except Exception:
        pass
    try:
        from huggingface_hub import HfFolder

        return HfFolder.get_token()
    except Exception:
        return None


def _print_auth_help() -> None:
    print(
        "No Hugging Face token found. Authenticate, then re-run:\n"
        "  huggingface-cli login        # or: hf auth login\n"
        "  # or set an env var:\n"
        "  export HF_TOKEN=hf_xxxxxxxxxxxxxxxxxxxxx\n"
        "  # or pass it explicitly (avoid in shell history):\n"
        "  python upload_to_hf.py --token hf_xxx\n",
        file=sys.stderr,
    )


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default=DEFAULT_REPO,
                    help=f"target dataset repo id (default: {DEFAULT_REPO})")
    ap.add_argument("--token", default=None,
                    help="HF token (prefer $HF_TOKEN or a cached login)")
    ap.add_argument("--private", action="store_true",
                    help="create the repo as private (default: public)")
    ap.add_argument("--dir", default=HERE, help="directory holding the dataset files")
    ap.add_argument("--commit-message", default="Add/update burpwn-usage dataset")
    ap.add_argument("--dry-run", action="store_true",
                    help="print what would be uploaded without contacting HF")
    args = ap.parse_args(argv)

    files = [f for f in DATASET_FILES if os.path.exists(os.path.join(args.dir, f))]
    missing = [f for f in DATASET_FILES if f not in files]
    if missing:
        print(f"note: skipping missing files: {', '.join(missing)} "
              "(run `python generate.py` to create the dataset files)", file=sys.stderr)
    if not any(f.endswith(".jsonl") for f in files):
        print("error: no dataset.*.jsonl files found — run `python generate.py` first.",
              file=sys.stderr)
        return 2

    if args.dry_run:
        print(f"[dry-run] would upload to dataset repo '{args.repo}' "
              f"({'private' if args.private else 'public'}):")
        for f in files:
            print(f"  - {f}")
        print("[dry-run] no token check, no network calls made.")
        return 0

    token = _resolve_token(args.token)
    if not token:
        _print_auth_help()
        return 1

    try:
        from huggingface_hub import HfApi
    except ImportError:
        print("error: huggingface_hub not installed. `pip install -r requirements.txt`.",
              file=sys.stderr)
        return 1

    api = HfApi(token=token)
    # Verify auth early with a friendly message.
    try:
        who = api.whoami()
        print(f"authenticated as: {who.get('name', '?')}", file=sys.stderr)
    except Exception as e:  # noqa: BLE001
        print(f"error: token rejected by Hugging Face: {e}", file=sys.stderr)
        _print_auth_help()
        return 1

    api.create_repo(repo_id=args.repo, repo_type="dataset",
                    private=args.private, exist_ok=True)

    for f in files:
        path = os.path.join(args.dir, f)
        print(f"uploading {f} → {args.repo} ...", file=sys.stderr)
        api.upload_file(
            path_or_fileobj=path,
            path_in_repo=f,
            repo_id=args.repo,
            repo_type="dataset",
            commit_message=args.commit_message,
        )

    print(f"done: https://huggingface.co/datasets/{args.repo}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
