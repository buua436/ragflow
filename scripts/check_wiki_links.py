#!/usr/bin/env python3
"""Check Wiki pages for empty, malformed, or dangling links.

Usage:
    python scripts/check_wiki_links.py wiki_pages.json

The input may be a single API response, a page list, or an object containing
``pages``/``items``.  The script only uses the standard library.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import unquote
from urllib.parse import quote
from urllib.request import Request, urlopen


# Fill in the token for the RAGFlow instance you want to inspect.
RAGFLOW_API_TOKEN = "ragflow-avjtoj5eYK_uBf4ET3-aGGSq-aQ9eHfAZATNLnkuksg"
RAGFLOW_API_URL = "http://127.0.0.1:9380/api/v1"
RAGFLOW_DATASET_ID = "13bf50828a4111f1bf2655d77366cc18"


EMPTY_WIKILINK_RE = re.compile(r"\[\[\s*(?:\|[^\]]*)?\s*\]\]")
WIKILINK_RE = re.compile(r"\[\[([^\[\]|]+?)(?:\|[^\[\]]*)?\]\]")
MARKDOWN_LINK_RE = re.compile(r"\[([^\]]*)\]\(([^)]*)\)")
ARTIFACT_LINK_RE = re.compile(r"\[([^\]]*)\]\(\s*artifact/([^)]*)\)")
BARE_ARTIFACT_RE = re.compile(r"(?<![\w/(])artifact/([^\s)\]<>\"']+)")


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return [value]
        return decoded if isinstance(decoded, list) else [decoded]
    return [value]


def _scalar(value: Any) -> str:
    values = _as_list(value)
    if not values:
        return ""
    return str(values[0] or "").strip()


def _page_slug(page: dict[str, Any]) -> str:
    slug = _scalar(page.get("slug") or page.get("slug_kwd"))
    if slug:
        return slug
    page_type = _scalar(page.get("page_type") or page.get("page_type_kwd"))
    title = _scalar(page.get("title") or page.get("title_kwd"))
    return f"{page_type}/{title}".strip("/") if page_type and title else title


def _looks_like_page(value: Any) -> bool:
    return isinstance(value, dict) and any(key in value for key in ("content_md_rendered", "md_with_weight", "content_with_weight", "slug", "slug_kwd"))


def _collect_pages(value: Any) -> list[dict[str, Any]]:
    pages: list[dict[str, Any]] = []
    seen: set[int] = set()

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            if _looks_like_page(node) and id(node) not in seen:
                seen.add(id(node))
                pages.append(node)
                return
            for child in node.values():
                visit(child)
        elif isinstance(node, list):
            for child in node:
                visit(child)

    visit(value)
    return pages


def _content(page: dict[str, Any]) -> str:
    for key in ("content_md_rendered", "md_with_weight", "content_with_weight", "content"):
        value = page.get(key)
        if isinstance(value, str):
            return value
    return ""


def _artifact_target(path: str) -> str | None:
    parts = [unquote(part).strip() for part in path.strip().split("/")]
    if parts and parts[0] == "artifact":
        parts = parts[1:]
    # artifact/<kb_id>/<entity|concept>/<slug>
    if len(parts) < 3 or not parts[0] or parts[1] not in {"entity", "concept"} or not parts[2]:
        return None
    return "/".join(parts[1:])


def check_pages(pages: list[dict[str, Any]]) -> dict[str, Any]:
    valid_slugs = {_page_slug(page) for page in pages if _page_slug(page)}
    issues: list[dict[str, Any]] = []

    def add(page_slug: str, kind: str, value: str, detail: str) -> None:
        issues.append({"page": page_slug, "kind": kind, "value": value, "detail": detail})

    for page in pages:
        page_slug = _page_slug(page) or "<unknown>"
        content = _content(page)

        for match in EMPTY_WIKILINK_RE.finditer(content):
            add(page_slug, "empty_wikilink", match.group(0), "empty [[...]] target")

        for match in WIKILINK_RE.finditer(content):
            target = match.group(1).strip()
            if target and target not in valid_slugs:
                add(page_slug, "dangling_wikilink", target, "target page does not exist")

        for match in MARKDOWN_LINK_RE.finditer(content):
            label, href = match.groups()
            if not href.strip():
                add(page_slug, "empty_markdown_link", match.group(0), "empty href")
            elif href.strip().startswith("artifact/"):
                target = _artifact_target(href)
                if target is None:
                    add(page_slug, "malformed_artifact_link", href, "invalid artifact path")
                elif target not in valid_slugs:
                    add(page_slug, "dangling_artifact_link", target, "target page does not exist")

        # A bare artifact path is not a clickable Markdown link.
        for match in BARE_ARTIFACT_RE.finditer(content):
            raw_path = f"artifact/{match.group(1)}"
            target = _artifact_target(raw_path)
            if target is None:
                add(page_slug, "malformed_bare_artifact_reference", raw_path, "bare artifact path is not a valid link")
            elif target not in valid_slugs:
                add(page_slug, "dangling_bare_artifact_reference", target, "bare artifact target page does not exist")
            else:
                add(page_slug, "bare_artifact_reference", raw_path, "artifact path is not wrapped in Markdown link syntax")

        for raw in _as_list(page.get("outlinks") or page.get("outlinks_kwd")):
            target = str(raw or "").strip()
            if not target:
                add(page_slug, "empty_outlink", repr(raw), "outlinks contains an empty value")
            elif target not in valid_slugs:
                add(page_slug, "dangling_outlink", target, "outlinks target does not exist")

    by_kind: dict[str, int] = {}
    for issue in issues:
        by_kind[issue["kind"]] = by_kind.get(issue["kind"], 0) + 1
    return {"pages": len(pages), "valid_slugs": len(valid_slugs), "issues": len(issues), "by_kind": by_kind, "details": issues}


def _api_get(url: str, token: str | None, cookie: str | None) -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if cookie:
        headers["Cookie"] = cookie
    request = Request(url, headers=headers)
    with urlopen(request, timeout=60) as response:  # noqa: S310 - URL is user supplied
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict) or payload.get("code") not in (None, 0):
        raise RuntimeError(f"API returned an error: {payload}")
    return payload


def fetch_pages_from_api(base_url: str, dataset_id: str, token: str | None, cookie: str | None, page_size: int) -> list[dict[str, Any]]:
    """List Wiki pages and fetch each page's Markdown through the REST API."""
    root = base_url.rstrip("/")
    page_size = max(1, min(page_size, 100))
    pages: list[dict[str, Any]] = []
    page = 1
    while True:
        list_url = f"{root}/datasets/{quote(dataset_id, safe='')}/artifacts?page={page}&page_size={page_size}"
        listing = _api_get(list_url, token, cookie).get("data") or {}
        items = listing.get("items") or []
        if not items:
            break
        for item in items:
            slug = _scalar(item.get("slug"))
            page_type = _scalar(item.get("page_type"))
            if not slug or "/" not in slug:
                continue
            if not page_type:
                page_type, slug_tail = slug.split("/", 1)
            else:
                slug_tail = slug.split("/", 1)[1]
            detail_url = f"{root}/datasets/{quote(dataset_id, safe='')}/artifacts/{quote(page_type, safe='')}/{quote(slug_tail, safe='/')}"
            detail = _api_get(detail_url, token, cookie).get("data")
            if isinstance(detail, dict):
                detail.setdefault("slug", slug)
                detail.setdefault("page_type", page_type)
                pages.append(detail)
        if len(pages) >= int(listing.get("total") or 0) or len(items) < page_size:
            break
        page += 1
    return pages


def _artifact_targets(pages: list[dict[str, Any]]) -> set[str]:
    targets: set[str] = set()
    for page in pages:
        content = _content(page)
        for _, href in MARKDOWN_LINK_RE.findall(content):
            if href.strip().startswith("artifact/"):
                target = _artifact_target(href.strip())
                if target:
                    targets.add(target)
        for match in BARE_ARTIFACT_RE.finditer(content):
            target = _artifact_target(f"artifact/{match.group(1)}")
            if target:
                targets.add(target)
    return targets


def find_missing_api_targets(
    pages: list[dict[str, Any]],
    base_url: str,
    dataset_id: str,
    token: str | None,
    cookie: str | None,
) -> list[dict[str, str]]:
    """Verify every artifact target against its page-detail endpoint."""
    root = base_url.rstrip("/")
    missing = []
    for target in sorted(_artifact_targets(pages)):
        page_type, slug = target.split("/", 1)
        detail_url = f"{root}/datasets/{quote(dataset_id, safe='')}/artifacts/{quote(page_type, safe='')}/{quote(slug, safe='/')}"
        try:
            data = _api_get(detail_url, token, cookie).get("data")
        except (OSError, RuntimeError, ValueError) as exc:
            missing.append({"target": target, "detail": f"detail API failed: {exc}"})
            continue
        if not isinstance(data, dict):
            missing.append({"target": target, "detail": "detail API returned no page"})
    return missing


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, nargs="?", help="JSON file exported from the Wiki API")
    parser.add_argument("--base-url", default=RAGFLOW_API_URL, help="RAGFlow API root")
    parser.add_argument("--dataset-id", default=RAGFLOW_DATASET_ID, help="fetch Wiki pages from this dataset through the API")
    parser.add_argument("--token", default=RAGFLOW_API_TOKEN, help="API token; defaults to the token in this script")
    parser.add_argument("--cookie", help="optional session Cookie header")
    parser.add_argument("--page-size", type=int, default=100, help="API page size (maximum 100)")
    parser.add_argument("--report", type=Path, help="also write the full report as JSON")
    args = parser.parse_args()

    try:
        if args.dataset_id:
            pages = fetch_pages_from_api(args.base_url, args.dataset_id, args.token, args.cookie, args.page_size)
        elif args.input:
            payload = json.loads(args.input.read_text(encoding="utf-8"))
            pages = _collect_pages(payload)
        else:
            parser.error("provide INPUT or --dataset-id")
    except (OSError, json.JSONDecodeError, RuntimeError, ValueError) as exc:
        print(f"failed to load Wiki pages: {exc}", file=sys.stderr)
        return 2

    report = check_pages(pages)
    if args.dataset_id:
        for missing in find_missing_api_targets(pages, args.base_url, args.dataset_id, args.token, args.cookie):
            report["details"].append(
                {
                    "page": "<api-validation>",
                    "kind": "api_missing_artifact_target",
                    "value": missing["target"],
                    "detail": missing["detail"],
                }
            )
        report["issues"] = len(report["details"])
        report["by_kind"] = {}
        for issue in report["details"]:
            report["by_kind"][issue["kind"]] = report["by_kind"].get(issue["kind"], 0) + 1
    print(json.dumps({key: value for key, value in report.items() if key != "details"}, ensure_ascii=False, indent=2))
    for issue in report["details"]:
        print(f"[{issue['kind']}] page={issue['page']} value={issue['value']!r}: {issue['detail']}")

    if args.report:
        args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return 1 if report["issues"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
