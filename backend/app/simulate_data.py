"""Generate synthetic DarkShield leak records and insert them into Supabase."""

from __future__ import annotations

import logging
import random
import string
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from faker import Faker


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db import get_supabase  # noqa: E402


LOGGER = logging.getLogger(__name__)
FAKER = Faker()
TOTAL_RECORDS = 150
BATCH_SIZE = 25
TABLE_NAME = "raw_pages"
SOURCE_TYPE = "simulated"
HTTP_STATUS = 200

SAFE_DOMAINS = [
    "example.com",
    "example.org",
    "corp-demo.test",
    "internal-lab.local",
    "sandbox-mail.net",
]

FORUM_OPENERS = [
    "fresh combo pack from internal panel",
    "dump mirrored from closed forum thread",
    "partial archive from staff portal leak",
    "new access list posted for verification",
    "chat export pulled from breach channel",
    "copy of leaked onboarding notes",
    "posting cleaned sample before full dump",
]

HACKER_LINES = [
    "anyone validate these entries yet?",
    "tokens looked active during the last check",
    "subset appears mixed with normal employee chatter",
    "need parser for the code fragments in this file",
    "looks like dev environment data with reused secrets",
    "mirror this quickly before the source disappears",
    "some rows are noise but the API material looks real",
]

CODE_SNIPPETS = [
    "curl -H 'Authorization: Bearer {token}' https://portal.{domain}/api/v1/users",
    "aws_access_key_id = '{token}'\naws_secret_access_key = 'fake-secret-placeholder'",
    "const githubToken = '{token}';\nfetch('https://{domain}/admin', {{ headers: {{ Authorization: githubToken }} }});",
    "SLACK_BOT_TOKEN='{token}'\npython notify.py --channel incidents",
    "client = ApiClient(base_url='https://{domain}')\nclient.login(api_key='{token}')",
]

BENIGN_TEMPLATES = [
    "Quarterly awareness memo for {name} at {domain}. Review the mock incident workbook and attend the training on {date}.",
    "Routine helpdesk transcript: {name} requested access to the sandbox at {domain}; callback number on file is {phone}.",
    "Internal admin note from {domain}: workstation {ip} passed the patch audit. Follow-up meeting with {name} scheduled for {date}.",
    "Security team chat excerpt: {name} is coordinating a table-top exercise for {domain}. No sensitive data attached.",
]


def configure_logging() -> None:
    """Configure terminal-friendly logging."""
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


def generate_api_key() -> str:
    """Generate a clearly fake API key using realistic prefixes."""
    prefix = random.choice(["sk-", "AKIA", "ghp_", "xoxb-"])
    alphabet = string.ascii_letters + string.digits
    suffix = "".join(random.choices(alphabet, k=random.randint(16, 28)))
    return f"{prefix}{suffix}"


def generate_fake_credential() -> str:
    """Generate a safe fake email/password pair."""
    username = FAKER.user_name()
    domain = random.choice(SAFE_DOMAINS)
    password = "".join(
        random.choices(string.ascii_letters + string.digits + "!@#$%", k=random.randint(10, 18))
    )
    return f"{username}@{domain}:{password}"


def generate_benign_text() -> str:
    """Generate a benign non-leak record."""
    return random.choice(BENIGN_TEMPLATES).format(
        name=FAKER.name(),
        domain=FAKER.domain_name(),
        phone=FAKER.phone_number(),
        ip=FAKER.ipv4(),
        date=FAKER.date_between(start_date="-30d", end_date="+30d").isoformat(),
    )


def _generate_url() -> str:
    domain = FAKER.domain_name()
    path = "/".join(FAKER.words(nb=random.randint(1, 3)))
    return f"https://{domain}/{path}"


def _generate_code_snippet() -> str:
    return random.choice(CODE_SNIPPETS).format(token=generate_api_key(), domain=FAKER.domain_name())


def _generate_indicator() -> str:
    indicator_type = random.choice(["credential", "api_key", "ip", "name", "domain", "message", "code"])

    if indicator_type == "credential":
        return generate_fake_credential()
    if indicator_type == "api_key":
        return generate_api_key()
    if indicator_type == "ip":
        return FAKER.ipv4()
    if indicator_type == "name":
        return FAKER.name()
    if indicator_type == "domain":
        return FAKER.domain_name()
    if indicator_type == "message":
        return random.choice(HACKER_LINES)
    return _generate_code_snippet()


def generate_fake_paste() -> str:
    """Generate a realistic synthetic breach-style text blob."""
    if random.random() < 0.25:
        return generate_benign_text()

    fragments: list[str] = [random.choice(FORUM_OPENERS)]
    fragments.extend(_generate_indicator() for _ in range(random.randint(1, 5)))
    fragments.extend(
        [
            f"thread_id={FAKER.uuid4()}",
            f"captured_at={datetime.now(timezone.utc).isoformat()}",
            f"operator_note={random.choice(HACKER_LINES)}",
        ]
    )

    if random.random() < 0.45:
        fragments.append(f"domain_hint={FAKER.domain_name()}")
    if random.random() < 0.35:
        fragments.append(f"employee={FAKER.name()}")
    if random.random() < 0.35:
        fragments.append(f"src_ip={FAKER.ipv4()}")
    if random.random() < 0.40:
        fragments.append(f"snippet:\n{_generate_code_snippet()}")

    random.shuffle(fragments)
    separators = ["\n", "\n\n", "\r\n", "\n- ", "\n> ", " | "]
    text = fragments[0]
    for fragment in fragments[1:]:
        text += random.choice(separators) + fragment
    return text


def build_record() -> dict[str, Any]:
    """Build one row matching the raw_pages schema exactly."""
    return {
        "url": _generate_url(),
        "raw_text": generate_fake_paste(),
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "http_status": HTTP_STATUS,
        "source_type": SOURCE_TYPE,
    }


def chunk_records(records: list[dict[str, Any]], size: int) -> Iterable[list[dict[str, Any]]]:
    """Yield fixed-size batches of records."""
    for start in range(0, len(records), size):
        yield records[start : start + size]


def _format_supabase_error(exc: Exception) -> str:
    """Extract the most useful Supabase error payload available."""
    response = getattr(exc, "response", None)
    if response is not None:
        try:
            return str(response.json())
        except Exception:
            return str(getattr(response, "text", response))
    return str(exc)


def insert_batches(records: list[dict[str, Any]]) -> int:
    """Insert generated records into Supabase in chunks."""
    client = get_supabase()
    if client is None:
        LOGGER.error("Supabase client is unavailable; aborting insert.")
        print("[ERROR] Supabase client is unavailable")
        return 0

    inserted_count = 0
    for batch_index, batch in enumerate(chunk_records(records, BATCH_SIZE), start=1):
        try:
            client.table(TABLE_NAME).insert(batch).execute()
            inserted_count += len(batch)
            LOGGER.info("[SUCCESS] Inserted batch %s successfully", batch_index)
            print(f"[SUCCESS] Inserted batch {batch_index} successfully")
        except Exception as exc:
            error_details = _format_supabase_error(exc)
            LOGGER.exception("Batch %s insert failed: %s", batch_index, error_details)
            print(f"[ERROR] Insert failed for batch {batch_index}")
            print(f"[ERROR] Supabase response: {error_details}")
            break

    return inserted_count


def main() -> None:
    """Generate and insert synthetic raw_pages rows."""
    configure_logging()
    print("====================================")
    print("DARKSHIELD SYNTHETIC DATA GENERATOR")
    print("====================================")

    try:
        records: list[dict[str, Any]] = []
        for index in range(1, TOTAL_RECORDS + 1):
            records.append(build_record())
            if index % BATCH_SIZE == 0 or index == TOTAL_RECORDS:
                LOGGER.info("[INFO] Generated %s/%s records", index, TOTAL_RECORDS)
                print(f"[INFO] Generated {index}/{TOTAL_RECORDS} records")

        inserted_count = insert_batches(records)
        if inserted_count == TOTAL_RECORDS:
            LOGGER.info("[SUCCESS] Inserted all %s simulated records", inserted_count)
            print(f"[SUCCESS] Inserted {inserted_count}/{TOTAL_RECORDS} records into `{TABLE_NAME}`")
        else:
            LOGGER.error("Inserted %s of %s records", inserted_count, TOTAL_RECORDS)
            print(f"[ERROR] Final success count: {inserted_count}/{TOTAL_RECORDS}")
    except Exception as exc:
        LOGGER.exception("Unexpected error during synthetic data generation: %s", exc)
        print(f"[ERROR] Unexpected error: {exc}")


if __name__ == "__main__":
    main()
