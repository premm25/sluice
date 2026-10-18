"""Heuristic capability labelling for tools that the policy doesn't label.

Deliberately conservative toward ``sink``: a missed sink is a missed
exfiltration, while an extra sink label only costs a fingerprint lookup.
Explicit ``[[tools]]`` entries in the policy always override these guesses.
"""

from __future__ import annotations

import re
from typing import Any

from sluice.flow import PRIVATE, SINK, UNTRUSTED

SINK_VERBS = {
    "send", "post", "publish", "upload", "notify", "tweet", "submit", "forward", "reply",
    "comment", "share", "push", "invite", "transfer", "pay", "webhook", "dm", "sms", "broadcast",
    "email", "mail", "message",
}
EGRESS_WORDS = {"http", "https", "request", "fetch", "curl", "wget", "navigate", "browse", "open_url"}
UNTRUSTED_WORDS = {
    "fetch", "browse", "browser", "scrape", "crawl", "web", "url", "search", "download", "inbox",
    "issue", "issues", "comments", "rss", "feed", "page", "website", "navigate", "html", "tweets",
    "reviews", "emails", "messages", "pull", "pr", "prs", "discussion", "discussions",
    "email", "mail", "message", "comment", "slack", "chat",
}
WRITE_VERBS = {"create", "add", "update", "open", "edit", "new"}
PUBLIC_OBJECTS = {"issue", "comment", "pr", "gist", "post", "page", "discussion", "message", "review", "release"}
PRIVATE_WORDS = {
    "file", "files", "read", "query", "sql", "db", "database", "secret", "secrets", "env",
    "credential", "credentials", "password", "passwords", "calendar", "contact", "contacts",
    "note", "notes", "drive", "doc", "docs", "document", "documents", "repo", "repository",
    "memory", "history", "inbox", "email", "emails", "mail", "messages", "dms", "customer",
    "customers", "record", "records", "table", "tables", "vault", "keychain", "clipboard",
}
READ_VERBS = {"read", "get", "list", "search", "query", "fetch", "find", "show", "view", "open", "cat", "load"}
SINK_PARAMS = {
    "url", "uri", "endpoint", "webhook", "webhook_url", "to", "recipient", "recipients",
    "channel", "channel_id", "email", "address", "cc", "bcc", "phone", "host", "destination",
}


def tokenize(name: str) -> set[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return {t for t in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if t}


def auto_labels(name: str, tool: dict[str, Any] | None = None) -> set[str]:
    tokens = tokenize(name)
    props: set[str] = set()
    if tool:
        schema = tool.get("inputSchema") or {}
        if isinstance(schema, dict) and isinstance(schema.get("properties"), dict):
            props = {p.lower() for p in schema["properties"]}

    labels: set[str] = set()
    is_sink_verb = bool(tokens & SINK_VERBS) and not (tokens & READ_VERBS)
    # create_issue, add_comment, update_gist ... publish content somewhere others can read it.
    publishes = bool(tokens & WRITE_VERBS and tokens & PUBLIC_OBJECTS)
    if is_sink_verb or publishes or tokens & EGRESS_WORDS or props & SINK_PARAMS:
        labels.add(SINK)
    if not (is_sink_verb or publishes) and (tokens & UNTRUSTED_WORDS or props & {"url", "uri"}):
        labels.add(UNTRUSTED)
    if tokens & PRIVATE_WORDS and not is_sink_verb and not (tokens & {"web", "url", "browse", "browser"}):
        labels.add(PRIVATE)
    return labels
