"""数据库归档（SQLite 在线备份）与只读核验命令。

容器内命令（源库路径沿用 app.config.DB_PATH，即环境变量 DB_PATH，
默认 $DATA_DIR/handoff.db）：

    python -m app.backup create <目录>   # 生成一致快照归档
    python -m app.backup verify <目录>   # 只读核验既有归档

create 的语义
-------------
1. 通过 SQLite 在线备份 API（sqlite3.Connection.backup，即 C 接口
   sqlite3_backup_*）从源库拷贝快照：源库以 **只读** 方式打开，API 持续
   写入、WAL 尚未合并（未 checkpoint）时也能得到一份**完整一致的已提交
   快照**，且绝不改动源库；
2. 备份产物先写入 **目标父目录内的暂存目录**（与目标同一文件系统），并把
   暂存库规范化为回滚日志模式（journal_mode=DELETE）——在线备份会继承
   源库的 WAL 模式标记，规范化后归档库脱离源库的 -wal/-shm 也能被任何
   SQLite 连接**独立只读打开**；
3. 对暂存库执行 integrity_check、foreign_key_check 与五张业务表
   （chains / events / offers / offer_witnesses / chain_seals）结构校验，
   全部通过后生成 manifest.json 清单（格式版本、创建时间、源库路径、
   各文件 SHA-256 与字节数），然后把整个归档目录 **原子 rename 发布** 到
   目标位置；
4. 目标已存在、或目标与源库路径（含其 -wal/-shm/-journal 伴生路径）
   冲突时拒绝；任何失败都清理暂存目录，不改动源库与既有归档。

verify 的语义
-------------
只读核验：清单结构与格式版本、归档条目与清单一致（无缺项、无清单未记录
的多余条目）、各文件 SHA-256 与字节数、以及上述三项数据库检查。任一不符
以非零退出码退出并在 stderr 报告具体原因。核验全程只读打开数据库，不在
归档目录内产生任何文件。

退出码：0 成功；1 失败（原因见 stderr）；2 命令行用法错误（argparse）。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import config

# 归档格式版本：清单结构或五张业务表结构发生变化时递增。
FORMAT_VERSION = 1

MANIFEST_NAME = "manifest.json"

# 五张业务表的期望结构，取自 PRAGMA table_info 的
# (name, type, notnull, dflt_value, pk)，与 app/database.py 的 _SCHEMA
# 一一对应（含旧 offers 表重建迁移后的最终结构）。表结构变更时必须同步
# 更新此处并递增 FORMAT_VERSION。
_EXPECTED_TABLES: dict[str, list[tuple[str, str, int, Any, int]]] = {
    "chains": [
        ("chain_id", "TEXT", 0, None, 1),
        ("file_hash", "TEXT", 1, None, 0),
        ("first_holder", "TEXT", 1, None, 0),
        ("tail_hash", "TEXT", 1, None, 0),
        ("current_holder", "TEXT", 1, None, 0),
        ("created_at", "TEXT", 1, None, 0),
    ],
    "events": [
        ("id", "INTEGER", 0, None, 1),
        ("chain_id", "TEXT", 1, None, 0),
        ("seq", "INTEGER", 1, None, 0),
        ("prev_hash", "TEXT", 1, "''", 0),
        ("giver", "TEXT", 1, "''", 0),
        ("receiver", "TEXT", 1, "''", 0),
        ("nonce", "TEXT", 1, "''", 0),
        ("event_hash", "TEXT", 1, None, 0),
        ("canonical", "TEXT", 1, None, 0),
        ("created_at", "TEXT", 1, None, 0),
    ],
    "offers": [
        ("offer_id", "TEXT", 0, None, 1),
        ("chain_id", "TEXT", 1, None, 0),
        ("tail_hash", "TEXT", 1, None, 0),
        ("receiver", "TEXT", 1, None, 0),
        ("code_digest", "TEXT", 1, None, 0),
        ("witness_threshold", "INTEGER", 0, None, 0),
        ("status", "TEXT", 1, "'pending'", 0),
        ("expires_at", "TEXT", 1, None, 0),
        ("created_at", "TEXT", 1, None, 0),
        ("accepted_at", "TEXT", 0, None, 0),
        ("accepted_seq", "INTEGER", 0, None, 0),
        ("cancel_code_digest", "TEXT", 0, None, 0),
        ("cancelled_at", "TEXT", 0, None, 0),
        ("replaces", "TEXT", 0, None, 0),
        ("replaced_by", "TEXT", 0, None, 0),
        ("replaced_at", "TEXT", 0, None, 0),
    ],
    "offer_witnesses": [
        ("id", "INTEGER", 0, None, 1),
        ("offer_id", "TEXT", 1, None, 0),
        ("witness_index", "INTEGER", 1, None, 0),
        ("name", "TEXT", 1, None, 0),
        ("token_digest", "TEXT", 1, None, 0),
        ("decision", "TEXT", 0, None, 0),
        ("decided_at", "TEXT", 0, None, 0),
    ],
    "chain_seals": [
        ("id", "INTEGER", 0, None, 1),
        ("seal_id", "TEXT", 1, None, 0),
        ("chain_id", "TEXT", 1, None, 0),
        ("tail_hash", "TEXT", 1, None, 0),
        ("reason", "TEXT", 1, None, 0),
        ("status", "TEXT", 1, "'active'", 0),
        ("release_code_digest", "TEXT", 1, None, 0),
        ("expires_at", "TEXT", 1, None, 0),
        ("created_at", "TEXT", 1, None, 0),
        ("released_at", "TEXT", 0, None, 0),
    ],
}

# 源库的伴生文件路径后缀：目标路径与之冲突同样拒绝
_JOURNAL_SUFFIXES = ("-wal", "-shm", "-journal")


class BackupError(Exception):
    """可归因的归档失败（消息直接面向操作者）。"""


def _sha256_file(path: Path) -> str:
    """流式计算文件 SHA-256（十六进制小写）。"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _fsync_file(path: Path) -> None:
    with open(path, "rb") as f:
        os.fsync(f.fileno())


def _fsync_dir(path: Path) -> None:
    """尽力而为的目录 fsync（保证目录项落盘）；不支持时忽略。"""
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _check_database(db_file: Path) -> list[str]:
    """对数据库文件执行只读校验，返回问题列表（空列表表示全部通过）。

    三项检查：integrity_check、foreign_key_check、五张业务表结构校验。
    全程只读打开（URI mode=ro），不产生任何伴生文件、不改动被检文件。
    """
    problems: list[str] = []
    try:
        conn = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        return [f"无法以只读方式打开数据库 {db_file}: {exc}"]
    try:
        conn.execute("PRAGMA busy_timeout = 5000")
        # 1) 完整性
        try:
            rows = [r[0] for r in conn.execute("PRAGMA integrity_check")]
            if rows != ["ok"]:
                problems.append(
                    "integrity_check 未通过: " + "; ".join(str(r) for r in rows[:5])
                )
        except sqlite3.Error as exc:
            problems.append(f"integrity_check 执行失败: {exc}")
        # 2) 外键一致性
        try:
            fk_rows = conn.execute("PRAGMA foreign_key_check").fetchall()
            if fk_rows:
                sample = "; ".join(str(tuple(r)) for r in fk_rows[:5])
                problems.append(
                    f"foreign_key_check 发现 {len(fk_rows)} 处外键违规: {sample}"
                )
        except sqlite3.Error as exc:
            problems.append(f"foreign_key_check 执行失败: {exc}")
        # 3) 五张业务表结构
        for table, expected in _EXPECTED_TABLES.items():
            try:
                info = conn.execute(f"PRAGMA table_info({table})").fetchall()
            except sqlite3.Error as exc:
                problems.append(f"读取业务表 {table} 结构失败: {exc}")
                continue
            actual = [
                (r[1], str(r[2]).upper(), r[3], r[4], r[5]) for r in info
            ]
            if not actual:
                problems.append(f"业务表 {table} 不存在")
            elif actual != expected:
                problems.append(
                    f"业务表 {table} 结构不符: 期望 {expected}，实际 {actual}"
                )
    finally:
        conn.close()
    return problems


def _run_online_backup(src_db: Path, staged_db: Path) -> None:
    """SQLite 在线备份：源库只读打开，目标为暂存新库。

    备份 API 在源库持续写入、WAL 未合并时也能拷贝出完整一致的已提交
    快照（源库在备份期间被修改时备份机制自动重传相应页面）。完成后把
    暂存库规范化为回滚日志模式，使其脱离源库 -wal/-shm 也独立可读。
    """
    try:
        src = sqlite3.connect(f"file:{src_db}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise BackupError(f"无法只读打开源数据库 {src_db}: {exc}") from exc
    try:
        src.execute("PRAGMA busy_timeout = 10000")
        dst = sqlite3.connect(str(staged_db))
        try:
            dst.execute("PRAGMA busy_timeout = 10000")
            # 在线备份：等效 sqlite3 命令的 .backup，源库保持在线可写
            src.backup(dst)
            # 备份产物继承源库的 WAL 模式标记；规范化为回滚日志模式，
            # 得到独立可读（无需 -wal/-shm 伴生文件）的归档库文件。
            mode = dst.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
            if str(mode).lower() != "delete":
                raise BackupError(
                    f"暂存快照日志模式规范化失败: journal_mode={mode}"
                )
        finally:
            dst.close()
    except sqlite3.Error as exc:
        raise BackupError(f"在线备份失败: {exc}") from exc
    finally:
        src.close()
    # 防御性清理伴生文件（正常时 journal_mode=DELETE 已移除）
    for suffix in _JOURNAL_SUFFIXES:
        stray = staged_db.with_name(staged_db.name + suffix)
        if stray.exists():
            stray.unlink()


def _write_manifest(staging: Path, db_name: str, digest: str, size: int) -> dict:
    manifest = {
        "format_version": FORMAT_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_db_path": str(config.DB_PATH),
        "database": db_name,
        "files": {db_name: {"sha256": digest, "size_bytes": size}},
    }
    manifest_path = staging / MANIFEST_NAME
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    return manifest


def create_archive(target: Path) -> dict:
    """创建归档：暂存 -> 校验 -> 原子发布。失败抛 BackupError 并清理暂存。"""
    src_db = Path(config.DB_PATH)
    if not src_db.is_file():
        raise BackupError(
            f"源数据库不存在: {src_db}（请先启动服务完成初始化，或检查 DB_PATH 配置）"
        )

    target_abs = Path(os.path.abspath(target))
    if os.path.lexists(target_abs):
        raise BackupError(f"目标已存在，拒绝覆盖: {target_abs}")

    # 目标与源库路径冲突：目标就是源库（或其 -wal/-shm/-journal 伴生路径），
    # 或目标是包含源库的上级目录（发布会替换掉源库所在目录）。
    db_real = src_db.resolve()
    target_real = target_abs.resolve()
    conflict_paths = [db_real] + [
        db_real.with_name(db_real.name + suffix) for suffix in _JOURNAL_SUFFIXES
    ]
    for conflict in conflict_paths:
        if target_real == conflict:
            raise BackupError(
                f"目标路径与源库路径冲突: {target_abs} 即源库路径 {conflict}"
            )
    if db_real.is_relative_to(target_real):
        raise BackupError(
            f"目标路径与源库路径冲突: {target_abs} 是源库 {db_real} 的上级目录"
        )

    # 在目标父目录内暂存（与目标同一文件系统，保证 rename 原子发布）
    parent = target_abs.parent
    parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{target_abs.name}.staging-", dir=parent)
    )
    published = False
    try:
        db_name = src_db.name
        staged_db = staging / db_name
        _run_online_backup(src_db, staged_db)

        # 发布前校验：integrity_check / foreign_key_check / 五张业务表结构
        problems = _check_database(staged_db)
        if problems:
            raise BackupError("暂存快照校验未通过: " + "; ".join(problems))
        _fsync_file(staged_db)

        digest = _sha256_file(staged_db)
        size = staged_db.stat().st_size
        manifest = _write_manifest(staging, db_name, digest, size)
        _fsync_dir(staging)

        # 发布前最后一次存在性检查（缩小与并发创建者的竞态窗口），
        # 随后原子 rename 发布整个归档目录。
        if os.path.lexists(target_abs):
            raise BackupError(f"目标已存在，拒绝覆盖: {target_abs}")
        os.rename(staging, target_abs)
        published = True
        _fsync_dir(parent)
        manifest["archive_path"] = str(target_abs)
        return manifest
    finally:
        if not published:
            # 失败清理暂存；不触碰源库与任何既有归档
            shutil.rmtree(staging, ignore_errors=True)


def _is_safe_manifest_name(name: Any) -> bool:
    """清单记录的文件名必须是归档根目录下的普通文件名（防路径穿越）。"""
    return (
        isinstance(name, str)
        and name not in ("", ".", "..", MANIFEST_NAME)
        and "/" not in name
        and "\\" not in name
    )


def _is_hex64(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


def verify_archive(target: Path) -> list[str]:
    """只读核验归档，返回问题列表（空列表表示核验通过）。"""
    problems: list[str] = []
    target = Path(target)
    if not target.exists():
        return [f"归档不存在: {target}"]
    if not target.is_dir():
        return [f"归档路径不是目录: {target}"]

    # ---- 清单结构与格式版本 ----
    manifest_path = target / MANIFEST_NAME
    if not manifest_path.is_file():
        return [f"缺少清单文件: {manifest_path}"]
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return [f"清单不是合法 JSON: {manifest_path}: {exc}"]
    if not isinstance(manifest, dict):
        return [f"清单顶层必须是 JSON 对象: {manifest_path}"]
    version = manifest.get("format_version")
    if version != FORMAT_VERSION:
        return [
            f"不支持的归档格式版本: {version!r}（本工具支持版本 {FORMAT_VERSION}）"
        ]
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        return ["清单 files 字段缺失或为空"]
    for name, meta in files.items():
        if not _is_safe_manifest_name(name):
            return [f"清单含非法文件路径: {name!r}"]
        if (
            not isinstance(meta, dict)
            or not _is_hex64(meta.get("sha256"))
            or not isinstance(meta.get("size_bytes"), int)
            or meta.get("size_bytes", -1) < 0
        ):
            return [f"清单文件条目非法: {name}: {meta!r}"]
    db_name = manifest.get("database")
    if not isinstance(db_name, str) or db_name not in files:
        return [f"清单 database 字段缺失或未列入 files: {db_name!r}"]

    # ---- 归档条目与清单一致（无缺项、无多余条目）----
    expected_entries = {MANIFEST_NAME, *files}
    actual_entries = {p.name for p in target.iterdir()}
    for name in sorted(expected_entries - actual_entries):
        problems.append(f"缺少清单记录的文件: {name}")
    for name in sorted(actual_entries - expected_entries):
        problems.append(f"存在清单未记录的条目: {name}")

    # ---- 各文件 SHA-256 与字节数 ----
    for name in sorted(files):
        meta = files[name]
        file_path = target / name
        if not file_path.is_file():
            continue  # 缺项已在上面报告
        size = file_path.stat().st_size
        if size != meta["size_bytes"]:
            problems.append(
                f"文件 {name} 字节数不符: 清单 {meta['size_bytes']}，实际 {size}"
            )
        digest = _sha256_file(file_path)
        if digest != meta["sha256"]:
            problems.append(
                f"文件 {name} SHA-256 不匹配: 清单 {meta['sha256']}，实际 {digest}"
            )

    # ---- 数据库检查（integrity_check / foreign_key_check / 表结构）----
    db_file = target / db_name
    if db_file.is_file():
        problems.extend(_check_database(db_file))
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m app.backup",
        description=(
            "数据库归档与核验：create 用 SQLite 在线备份生成一致快照归档"
            "（源库由 DB_PATH 定位），verify 只读核验既有归档。"
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)
    p_create = sub.add_parser(
        "create",
        help="生成一致快照归档（在线备份，原子发布）",
        description=(
            "从 DB_PATH 指向的源库在线备份出一致快照，校验通过后原子发布到"
            "指定目录；目标已存在或与源库路径冲突时拒绝。"
        ),
    )
    p_create.add_argument("directory", type=Path, help="归档目标目录（不得已存在）")
    p_verify = sub.add_parser(
        "verify",
        help="只读核验既有归档",
        description=(
            "只读核验归档清单、文件 SHA-256 与数据库完整性/外键/表结构；"
            "损坏或缺项以非零退出码报告具体原因。"
        ),
    )
    p_verify.add_argument("directory", type=Path, help="待核验的归档目录")
    args = parser.parse_args(argv)

    if args.command == "create":
        try:
            manifest = create_archive(args.directory)
        except BackupError as exc:
            print(f"[backup] 失败: {exc}", file=sys.stderr)
            return 1
        except Exception as exc:  # 非预期错误同样清理后报告（暂存清理由 create_archive 保证）
            print(f"[backup] 失败: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        db_name = manifest["database"]
        meta = manifest["files"][db_name]
        print(f"[backup] 源数据库: {config.DB_PATH}")
        print(
            f"[backup] 快照校验通过: integrity_check / foreign_key_check / "
            f"五张业务表结构"
        )
        print(
            f"[backup] 归档已发布: {manifest['archive_path']} "
            f"（{db_name} {meta['size_bytes']} 字节, sha256={meta['sha256']}）"
        )
        return 0

    # verify
    try:
        problems = verify_archive(args.directory)
    except Exception as exc:
        print(f"[verify] 失败: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if problems:
        print(f"[verify] 归档核验未通过: {args.directory}", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(f"[verify] 归档核验通过: {args.directory}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
