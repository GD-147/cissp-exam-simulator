import json
import re
import sys
import textwrap
from pathlib import Path

ROOT = Path(".")
SOURCE = ROOT / "imports/cissp_exams/json"
DATA = ROOT / "packs/cissp/data"
PDF = ROOT / "packs/cissp/pdf"
CONFIG = ROOT / "packs/cissp/config.json"

EXAM = 2

DOMAINS = [
    (1, "Security and Risk Management", 24, 1, 24),
    (2, "Asset Security", 15, 25, 39),
    (3, "Security Architecture and Engineering", 20, 40, 59),
    (4, "Communication and Network Security", 19, 60, 78),
    (5, "Identity and Access Management (IAM)", 20, 79, 98),
    (6, "Security Assessment and Testing", 18, 99, 116),
    (7, "Security Operations", 19, 117, 135),
    (8, "Software Development Security", 15, 136, 150)
]

ROMANS = {
    1: "I", 2: "II", 3: "III", 4: "IV",
    5: "V", 6: "VI", 7: "VII", 8: "VIII"
}

ALIASES = {}

for number, name, count, start, end in DOMAINS:
    values = {
        str(number),
        ROMANS[number],
        f"DOMAIN {number}",
        f"DOMAIN {ROMANS[number]}",
        name.upper(),
        f"DOMAIN {number} - {name}".upper(),
        f"DOMAIN {number} — {name}".upper(),
        f"DOMAIN {ROMANS[number]} - {name}".upper(),
        f"DOMAIN {ROMANS[number]} — {name}".upper()
    }

    for value in values:
        ALIASES[value.strip().upper()] = name

ALIASES["IDENTITY AND ACCESS MANAGEMENT"] = \
    "Identity and Access Management (IAM)"
ALIASES["IAM"] = \
    "Identity and Access Management (IAM)"


def load_questions(path):
    raw = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(raw, list):
        return raw

    if isinstance(raw, dict):
        if isinstance(raw.get("questions"), list):
            return raw["questions"]

        if isinstance(raw.get("items"), list):
            return raw["items"]

    raise ValueError(
        "JSON must be an array or contain a questions array"
    )


def normalize_domain(value):
    raw = re.sub(
        r"\s+",
        " ",
        str(value or "").strip().upper()
    )

    return ALIASES.get(raw)


def parse_id(qid):
    m = re.fullmatch(
        r"CISSP(\d+)-(\d{3})",
        str(qid or "").strip()
    )

    if not m:
        return None, None

    return int(m.group(1)), int(m.group(2))


all_files = sorted(SOURCE.glob("*.json"))
candidates = []

print("=== SOURCE DISCOVERY ===")
print("All JSON files in import folder:", len(all_files))

for path in all_files:
    try:
        questions = load_questions(path)
    except Exception:
        continue

    ids = [
        str(q.get("id", "")).strip()
        for q in questions
        if isinstance(q, dict)
    ]

    exam_numbers = {
        parse_id(qid)[0]
        for qid in ids
        if parse_id(qid)[0] is not None
    }

    if EXAM in exam_numbers:
        candidates.append(path)

print("Exam 02 source files detected:", len(candidates))

for p in candidates:
    print("SOURCE:", p.name)

errors = []
notes = []
domain_files = {}
all_questions = []

if len(candidates) != 8:
    errors.append(
        f"Expected exactly 8 Exam 02 JSON files; found {len(candidates)}"
    )

for path in candidates:
    print()
    print("AUDITING:", path.name)

    try:
        questions = load_questions(path)
    except Exception as exc:
        errors.append(f"{path.name}: cannot load: {exc}")
        continue

    print("Questions:", len(questions))

    domains = set()

    for index, q in enumerate(questions, 1):
        if not isinstance(q, dict):
            errors.append(
                f"{path.name} question {index}: not an object"
            )
            continue

        qid = str(q.get("id", "")).strip()
        exam_no, sequence = parse_id(qid)

        if exam_no != EXAM or sequence is None:
            errors.append(
                f"{path.name} question {index}: invalid Exam 02 ID '{qid}'"
            )

        raw_domain = q.get(
            "domain",
            q.get("Domain", "")
        )

        domain = normalize_domain(raw_domain)

        if not domain:
            errors.append(
                f"{path.name} {qid}: unrecognized domain '{raw_domain}'"
            )
        else:
            domains.add(domain)

            if str(raw_domain).strip() != domain:
                notes.append(
                    f"{path.name} {qid}: "
                    f"'{raw_domain}' -> '{domain}'"
                )

        for field in [
            "prompt",
            "competency",
            "skill",
            "explanation"
        ]:
            if not str(q.get(field, "") or "").strip():
                errors.append(
                    f"{path.name} {qid}: missing {field}"
                )

        raw_type = str(
            q.get(
                "type",
                q.get("itemType", "")
            )
        ).strip().lower()

        if raw_type in {
            "mcq_single",
            "single",
            "multiple_choice"
        }:
            raw_type = "mcq"

        if raw_type in {
            "multiselect",
            "multiple_select"
        }:
            raw_type = "multi_select"

        if raw_type not in {
            "mcq",
            "multi_select"
        }:
            errors.append(
                f"{path.name} {qid}: unsupported type '{raw_type}'"
            )
            continue

        choices = q.get("choices")

        if not isinstance(choices, dict):
            errors.append(
                f"{path.name} {qid}: choices must be an object"
            )
            continue

        keys = [
            str(k).strip().upper()
            for k in choices.keys()
        ]

        texts = [
            re.sub(
                r"\s+",
                " ",
                str(v or "").strip()
            ).casefold()
            for v in choices.values()
        ]

        if any(not x for x in texts):
            errors.append(
                f"{path.name} {qid}: empty choice text"
            )

        if len(texts) != len(set(texts)):
            errors.append(
                f"{path.name} {qid}: duplicate choice text"
            )

        if raw_type == "mcq":
            if set(keys) != {"A", "B", "C", "D"}:
                errors.append(
                    f"{path.name} {qid}: MCQ must contain exactly A-D"
                )

            correct = str(
                q.get("correct", "")
            ).strip().upper()

            if correct not in keys:
                errors.append(
                    f"{path.name} {qid}: invalid correct answer '{correct}'"
                )

        if raw_type == "multi_select":
            answers = q.get("correctAnswers")

            if not isinstance(answers, list):
                errors.append(
                    f"{path.name} {qid}: correctAnswers array missing"
                )
            else:
                answers = [
                    str(x).strip().upper()
                    for x in answers
                ]

                if len(answers) < 2:
                    errors.append(
                        f"{path.name} {qid}: fewer than 2 correct answers"
                    )

                if len(answers) != len(set(answers)):
                    errors.append(
                        f"{path.name} {qid}: duplicate correctAnswers"
                    )

                for answer in answers:
                    if answer not in keys:
                        errors.append(
                            f"{path.name} {qid}: "
                            f"invalid correct answer '{answer}'"
                        )

        scenario = str(
            q.get("scenarioContext", "") or ""
        ).strip()

        flag = (
            q.get("isScenarioBased") is True
            or str(
                q.get("isScenarioBased", "")
            ).strip().lower() == "true"
        )

        if flag and not scenario:
            errors.append(
                f"{path.name} {qid}: "
                "isScenarioBased=true but scenarioContext empty"
            )

        if not flag and scenario:
            errors.append(
                f"{path.name} {qid}: "
                "scenarioContext present but isScenarioBased is not true"
            )

    if len(domains) != 1:
        errors.append(
            f"{path.name}: expected one domain; found {sorted(domains)}"
        )
        continue

    domain = next(iter(domains))

    if domain in domain_files:
        errors.append(
            f"Duplicate Exam 02 file for domain '{domain}'"
        )
    else:
        domain_files[domain] = path

    expected = next(
        d for d in DOMAINS
        if d[1] == domain
    )

    number, name, count, start, end = expected

    if len(questions) != count:
        errors.append(
            f"{path.name}: Domain {number} expected "
            f"{count} questions; found {len(questions)}"
        )

    sequences = []

    for q in questions:
        exam_no, seq = parse_id(
            q.get("id", "")
        )

        if exam_no == EXAM and seq is not None:
            sequences.append(seq)

    if sorted(sequences) != list(
        range(start, end + 1)
    ):
        errors.append(
            f"{path.name}: Domain {number} ID range must be "
            f"CISSP2-{start:03d} -> CISSP2-{end:03d}"
        )

    all_questions.extend(questions)


print()
print("=== DOMAIN FILE MAP ===")

for number, name, count, start, end in DOMAINS:
    p = domain_files.get(name)

    print(
        f"Domain {number}: "
        f"{p.name if p else 'MISSING'} | "
        f"{count}q | "
        f"CISSP2-{start:03d} -> CISSP2-{end:03d}"
    )


print()
print("=== GLOBAL ID AUDIT ===")

ids = [
    str(q.get("id", "")).strip()
    for q in all_questions
]

expected_ids = [
    f"CISSP2-{i:03d}"
    for i in range(1, 151)
]

duplicates = sorted({
    qid
    for qid in ids
    if ids.count(qid) > 1
})

print("Questions:", len(ids))
print("Unique IDs:", len(set(ids)))

if duplicates:
    errors.append(
        "Duplicate IDs: " + ", ".join(duplicates)
    )

missing = sorted(
    set(expected_ids) - set(ids)
)

extra = sorted(
    set(ids) - set(expected_ids)
)

if missing:
    errors.append(
        "Missing IDs: " + ", ".join(missing)
    )

if extra:
    errors.append(
        "Unexpected IDs: " + ", ".join(extra)
    )


print()
print("=== NORMALIZATION NOTES ===")

if notes:
    for note in notes[:60]:
        print("NOTE:", note)

    if len(notes) > 60:
        print(
            f"... {len(notes)-60} additional notes"
        )
else:
    print("None")


print()
print("=== ERRORS ===")

if errors:
    for error in errors:
        print("ERROR:", error)

    print()
    print("AUDIT RESULT: BLOCKED")
    print("IMPORT NOT PERFORMED")
    sys.exit(2)

print("None")
print()
print("AUDIT RESULT: CLEAN")


def canonicalize(q):
    out = dict(q)

    out["id"] = str(
        q.get("id", "")
    ).strip()

    domain = normalize_domain(
        q.get(
            "domain",
            q.get("Domain", "")
        )
    )

    out["domain"] = domain
    out.pop("Domain", None)

    qtype = str(
        q.get(
            "type",
            q.get("itemType", "")
        )
    ).strip().lower()

    if qtype in {
        "mcq_single",
        "single",
        "multiple_choice"
    }:
        qtype = "mcq"

    if qtype in {
        "multiselect",
        "multiple_select"
    }:
        qtype = "multi_select"

    out["type"] = qtype
    out.pop("itemType", None)

    out["choices"] = {
        str(k).strip().upper(): v
        for k, v in q.get(
            "choices",
            {}
        ).items()
    }

    if qtype == "mcq":
        out["correct"] = str(
            q.get("correct", "")
        ).strip().upper()

        out.pop(
            "correctAnswers",
            None
        )

    else:
        out["correctAnswers"] = sorted([
            str(x).strip().upper()
            for x in q.get(
                "correctAnswers",
                []
            )
        ])

        out.pop(
            "correct",
            None
        )

    scenario = str(
        q.get(
            "scenarioContext",
            ""
        ) or ""
    ).strip()

    flag = (
        q.get("isScenarioBased") is True
        or str(
            q.get(
                "isScenarioBased",
                ""
            )
        ).strip().lower() == "true"
    )

    out["isScenarioBased"] = bool(flag)

    if flag:
        out["scenarioContext"] = scenario
    else:
        out.pop(
            "scenarioContext",
            None
        )

    return out


master = []
domain_questions = {}

for number, name, count, start, end in DOMAINS:
    path = domain_files[name]
    questions = [
        canonicalize(q)
        for q in load_questions(path)
    ]

    questions.sort(
        key=lambda q: parse_id(q["id"])[1]
    )

    domain_questions[number] = questions
    master.extend(questions)

master.sort(
    key=lambda q: parse_id(q["id"])[1]
)

DATA.mkdir(
    parents=True,
    exist_ok=True
)

master_path = DATA / "cissp_exam_02.json"

master_path.write_text(
    json.dumps(
        {
            "examId": "cissp",
            "examNumber": 2,
            "title": "CISSP Full-Length Practice Exam 02",
            "questions": master
        },
        ensure_ascii=False,
        indent=2
    ) + "\n",
    encoding="utf-8"
)

print()
print("=== MASTER IMPORT ===")
print("CREATED:", master_path)
print("Questions:", len(master))
print("First ID:", master[0]["id"])
print("Last ID:", master[-1]["id"])


def clean_text(value):
    s = str(value or "")

    replacements = {
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2013": "-",
        "\u2014": "-",
        "\u2026": "...",
        "\u2022": "*",
        "\u2192": "->",
        "\u2190": "<-",
        "\u2265": ">=",
        "\u2264": "<=",
        "\u00a0": " ",
        "\u00d7": "x"
    }

    for a, b in replacements.items():
        s = s.replace(a, b)

    return s.encode(
        "cp1252",
        errors="replace"
    ).decode("cp1252")


def wrap_lines(text, width=92):
    result = []

    for paragraph in clean_text(
        text
    ).splitlines() or [""]:

        if not paragraph.strip():
            result.append("")
            continue

        result.extend(
            textwrap.wrap(
                paragraph,
                width=width,
                replace_whitespace=False,
                drop_whitespace=True
            ) or [""]
        )

    return result


def pdf_escape(value):
    return (
        clean_text(value)
        .replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )


def make_pdf(path, title, domain_no, questions):
    pages = []
    current = []
    max_lines = 53

    def push(line="", bold=False, size=10):
        nonlocal current

        if len(current) >= max_lines:
            pages.append(current)
            current = []

        current.append(
            (
                clean_text(line),
                bold,
                size
            )
        )

    def wrapped(
        value,
        indent="",
        bold=False,
        size=10,
        width=92
    ):
        for line in wrap_lines(
            value,
            width
        ):
            push(
                indent + line,
                bold,
                size
            )

    push(title, True, 14)
    push(
        f"Practice Exam 02 — Domain {domain_no}",
        True,
        11
    )
    push("")
    push(
        "Choose the best answer for each question. "
        "For multi-select items, select all required answers.",
        False,
        9
    )
    push("")

    for local_no, q in enumerate(
        questions,
        1
    ):
        push(
            f"Question {local_no} ({q['id']})",
            True,
            10
        )

        if (
            q.get("isScenarioBased")
            and q.get("scenarioContext")
        ):
            wrapped(
                "Scenario: "
                + q["scenarioContext"],
                size=9
            )
            push("")

        wrapped(
            q.get("prompt", ""),
            size=10
        )

        for letter in sorted(
            q.get("choices", {})
        ):
            wrapped(
                f"{letter}. "
                f"{q['choices'][letter]}",
                indent="   ",
                size=9,
                width=86
            )

        push("")

    if current:
        pages.append(current)
        current = []

    push(
        "ANSWER KEY AND EXPLANATIONS",
        True,
        14
    )
    push("")

    for local_no, q in enumerate(
        questions,
        1
    ):
        if q.get("type") == "multi_select":
            correct = ", ".join(
                q.get(
                    "correctAnswers",
                    []
                )
            )
        else:
            correct = q.get(
                "correct",
                ""
            )

        push(
            f"Question {local_no} ({q['id']}) — Correct: {correct}",
            True,
            10
        )

        wrapped(
            q.get(
                "explanation",
                ""
            ),
            size=9
        )

        push("")

    if current:
        pages.append(current)

    objects = []

    def obj(data):
        objects.append(data)
        return len(objects)

    regular = obj(
        b"<< /Type /Font /Subtype /Type1 "
        b"/BaseFont /Helvetica "
        b"/Encoding /WinAnsiEncoding >>"
    )

    bold = obj(
        b"<< /Type /Font /Subtype /Type1 "
        b"/BaseFont /Helvetica-Bold "
        b"/Encoding /WinAnsiEncoding >>"
    )

    page_ids = []
    content_ids = []

    for page in pages:
        commands = [
            "BT",
            "1 0 0 1 45 755 Tm"
        ]

        first = True

        for line, is_bold, size in page:
            font = "F2" if is_bold else "F1"

            if first:
                commands.append(
                    f"/{font} {size} Tf"
                )
                first = False
            else:
                commands.append(
                    "0 -13 Td"
                )
                commands.append(
                    f"/{font} {size} Tf"
                )

            commands.append(
                f"({pdf_escape(line)}) Tj"
            )

        commands.append("ET")

        stream = "\n".join(
            commands
        ).encode(
            "cp1252",
            errors="replace"
        )

        content = (
            f"<< /Length {len(stream)} >>\n"
            "stream\n"
        ).encode() + stream + b"\nendstream"

        content_ids.append(
            obj(content)
        )

        page_ids.append(
            obj(b"")
        )

    pages_id = obj(b"")

    for i, page_id in enumerate(
        page_ids
    ):
        objects[page_id - 1] = (
            f"<< /Type /Page "
            f"/Parent {pages_id} 0 R "
            f"/MediaBox [0 0 612 792] "
            f"/Resources << /Font << "
            f"/F1 {regular} 0 R "
            f"/F2 {bold} 0 R "
            f">> >> "
            f"/Contents {content_ids[i]} 0 R >>"
        ).encode()

    kids = " ".join(
        f"{pid} 0 R"
        for pid in page_ids
    )

    objects[pages_id - 1] = (
        f"<< /Type /Pages "
        f"/Kids [{kids}] "
        f"/Count {len(page_ids)} >>"
    ).encode()

    catalog_id = obj(
        f"<< /Type /Catalog "
        f"/Pages {pages_id} 0 R >>".encode()
    )

    data = bytearray(
        b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    )

    offsets = [0]

    for i, body in enumerate(
        objects,
        1
    ):
        offsets.append(
            len(data)
        )

        data.extend(
            f"{i} 0 obj\n".encode()
        )

        data.extend(body)
        data.extend(b"\nendobj\n")

    xref = len(data)

    data.extend(
        f"xref\n0 {len(objects)+1}\n".encode()
    )

    data.extend(
        b"0000000000 65535 f \n"
    )

    for offset in offsets[1:]:
        data.extend(
            f"{offset:010d} 00000 n \n".encode()
        )

    data.extend(
        (
            f"trailer\n"
            f"<< /Size {len(objects)+1} "
            f"/Root {catalog_id} 0 R >>\n"
            f"startxref\n{xref}\n"
            f"%%EOF\n"
        ).encode()
    )

    path.write_bytes(data)


print()
print("=== GENERATING PRINTABLE PDF 09-16 ===")

new_printables = []

for number, name, count, start, end in DOMAINS:
    pdf_no = number + 8

    filename = (
        f"cissp_printable_exam_{pdf_no:02d}.pdf"
    )

    label = (
        f"CISSP Printable Practice Exam {pdf_no:02d} "
        f"— Domain {number} — {name}"
    )

    make_pdf(
        PDF / filename,
        label,
        number,
        domain_questions[number]
    )

    print(
        f"CREATED: {filename} | "
        f"Practice Exam 02 | "
        f"Domain {number} | "
        f"{len(domain_questions[number])} questions"
    )

    new_printables.append({
        "label": label,
        "file": filename
    })


cfg = json.loads(
    CONFIG.read_text(
        encoding="utf-8"
    )
)

existing_exam_files = [
    x for x in cfg.get(
        "examFiles",
        []
    )
    if x != "cissp_exam_02.json"
]

if "cissp_exam_01.json" not in existing_exam_files:
    existing_exam_files.insert(
        0,
        "cissp_exam_01.json"
    )

cfg["examFiles"] = (
    existing_exam_files
    + ["cissp_exam_02.json"]
)

for section in cfg["sections"]:
    section["examFiles"] = list(
        cfg["examFiles"]
    )

old_printables = []

for item in cfg.get(
    "printables",
    []
):
    filename = item.get(
        "file",
        ""
    )

    match = re.search(
        r"cissp_printable_exam_(\d+)\.pdf$",
        filename
    )

    if not match:
        old_printables.append(item)
        continue

    number = int(
        match.group(1)
    )

    if not (9 <= number <= 16):
        old_printables.append(item)

cfg["printables"] = (
    old_printables
    + new_printables
)

def printable_number(item):
    m = re.search(
        r"_(\d+)\.pdf$",
        item.get(
            "file",
            ""
        )
    )

    return int(
        m.group(1)
    ) if m else 999999

cfg["printables"].sort(
    key=printable_number
)

CONFIG.write_text(
    json.dumps(
        cfg,
        ensure_ascii=False,
        indent=2
    ) + "\n",
    encoding="utf-8"
)

print()
print("=== CONFIG UPDATED ===")
print(
    "examFiles:",
    cfg["examFiles"]
)
print(
    "printables:",
    len(cfg["printables"])
)

for i, item in enumerate(
    cfg["printables"],
    1
):
    print(
        f"{i:02d} | "
        f"{item['file']}"
    )


print()
print("=== POST-IMPORT AUDIT ===")

loaded = json.loads(
    master_path.read_text(
        encoding="utf-8"
    )
)

questions = loaded["questions"]

post_errors = []

if len(questions) != 150:
    post_errors.append(
        "Master does not contain 150 questions"
    )

actual_ids = [
    q["id"]
    for q in questions
]

if actual_ids != expected_ids:
    post_errors.append(
        "Master ID sequence is not CISSP2-001 -> CISSP2-150"
    )

for number, name, count, start, end in DOMAINS:
    found = sum(
        1
        for q in questions
        if q["domain"] == name
    )

    print(
        f"Domain {number}: "
        f"{found}/{count}"
    )

    if found != count:
        post_errors.append(
            f"Domain {number} count mismatch"
        )

if post_errors:
    for error in post_errors:
        print(
            "ERROR:",
            error
        )

    print(
        "POST-IMPORT AUDIT: PROBLEM"
    )
    sys.exit(3)

print("Total: 150/150")
print(
    "IDs: CISSP2-001 -> CISSP2-150"
)
print(
    "POST-IMPORT AUDIT: CLEAN"
)
