"""Adversarial corpus: actions whose *effect* is dangerous but whose *arguments*
are crafted to slip past signature / keyword scanning.

Each case declares the ground-truth label and, for protected-resource policy,
which resources are precious. SQL cases carry their schema setup so the SqlAdapter
can really simulate against a populated database.

The point is not that simdiff is clever — it is that deciding over the simulated
effect is structurally immune to argument obfuscation, while keyword scanning is
not.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Set


@dataclass
class Case:
    id: str
    domain: str  # "shell" | "sql"
    action: str
    label: str  # "dangerous" | "safe"
    technique: str
    existing: Set[str] = field(default_factory=set)  # shell: pre-existing paths
    protected: Set[str] = field(default_factory=set)  # resources a policy guards
    setup: List[str] = field(default_factory=list)  # sql: schema/seed statements


CASES: List[Case] = [
    # --- dangerous, obfuscated: keyword scanning misses, effect simulation does not ---
    Case(
        id="rm-no-rf-flag",
        domain="shell",
        action="rm prod.db",
        label="dangerous",
        technique="signature too specific (denylist expects 'rm -rf')",
        existing={"prod.db"},
        protected={"prod.db"},
    ),
    Case(
        id="delete-by-move",
        domain="shell",
        action="mv prod.db /dev/null",
        label="dangerous",
        technique="deletion expressed as a move, no 'rm' token",
        existing={"prod.db"},
        protected={"prod.db"},
    ),
    Case(
        id="find-delete",
        domain="shell",
        action="find . -name '*.db' -delete",
        label="dangerous",
        technique="destruction via an uninterpreted tool -> fail-closed",
        existing={"prod.db"},
        protected={"prod.db"},
    ),
    Case(
        id="chmod-symbolic",
        domain="shell",
        action="chmod u=rwx,go=rwx secrets.env",
        label="dangerous",
        technique="permission widening via symbolic mode, not '777'",
        existing={"secrets.env"},
        protected={"secrets.env"},
    ),
    Case(
        id="drop-comment-obfuscated",
        domain="sql",
        action="DROP/**/TABLE users",
        label="dangerous",
        technique="SQL comment splits the 'DROP TABLE' signature",
        protected={"users"},
        setup=["CREATE TABLE users (id INTEGER)", "INSERT INTO users VALUES (1)"],
    ),
    Case(
        id="delete-comment-obfuscated",
        domain="sql",
        action="DELETE/**/FROM accounts",
        label="dangerous",
        technique="SQL comment breaks the 'DELETE FROM' signature",
        protected={"accounts"},
        setup=["CREATE TABLE accounts (id INTEGER)", "INSERT INTO accounts VALUES (1)"],
    ),
    # --- dangerous, plain: both approaches should catch (simdiff must not be worse) ---
    Case(
        id="rm-rf-plain",
        domain="shell",
        action="rm -rf prod_data",
        label="dangerous",
        technique="obvious destructive command",
        existing={"prod_data"},
        protected={"prod_data"},
    ),
    Case(
        id="drop-table-plain",
        domain="sql",
        action="DROP TABLE users",
        label="dangerous",
        technique="obvious destructive statement",
        protected={"users"},
        setup=["CREATE TABLE users (id INTEGER)"],
    ),
    # --- safe: must NOT be flagged (false-positive test) ---
    Case(id="mkdir", domain="shell", action="mkdir build", label="safe", technique="create dir"),
    Case(
        id="cp-into-docs",
        domain="shell",
        action="cp README.md docs/README.md",
        label="safe",
        technique="copy a file",
        existing={"README.md"},
    ),
    Case(id="touch-log", domain="shell", action="touch logs/app.log", label="safe", technique="create file"),
    Case(
        id="benign-cleanup",
        domain="shell",
        action="rm tmp/scratch.txt",
        label="safe",
        technique="delete a non-protected scratch file",
        existing={"tmp/scratch.txt"},
        protected={"prod.db"},
    ),
    Case(
        id="select",
        domain="sql",
        action="SELECT * FROM users",
        label="safe",
        technique="read-only query",
        setup=["CREATE TABLE users (id INTEGER)"],
    ),
    Case(
        id="insert-log",
        domain="sql",
        action="INSERT INTO logs (msg) VALUES ('ok')",
        label="safe",
        technique="append to a non-protected table",
        setup=["CREATE TABLE logs (msg TEXT)"],
    ),
]
