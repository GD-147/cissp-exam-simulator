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

EXAM = 1

DOMAINS = [
    {
        "number": 1,
        "name": "Security and Risk Management",
        "count": 24,
        "start": 1,
        "end": 24,
        "pdf": 1
    },
    {
        "number": 2,
        "name": "Asset Security",
        "count": 15,
        "start": 25,
        "end": 39,
        "pdf": 2
    },
    {
        "number": 3,
        "name": "Security Architecture and Engineering",
        "count": 20,
        "start": 40,
        "end": 59,
        "pdf": 3
    },
    {
        "number": 4,
        "name": "Communication and Network Security",
        "count": 19,
        "start": 60,
        "end": 78,
        "pdf": 4
    },
    {
        "number": 5,
        "name": "Identity and Access Management (IAM)",
        "count": 20,
        "start": 79,
        "end": 98,
        "pdf": 5
    },
    {
        "number": 6,
        "name": "Security Assessment and Testing",
        "count": 18,
        "start": 99,
        "end": 116,
        "pdf": 6
    },
    {
        "number": 7,
        "name": "Security Operations",
        "count": 19,
        "start": 117,
        "end": 135,
        "pdf": 7
    },
    {
        "number": 8,
        "name": "Software Development Security",
        "count": 15,
        "start": 136,
        "end": 150,
        "pdf": 8
    }
]

ALIASES = {}

ROMANS = {
    1: "I",
    2: "II",
    3: "III",
    4: "IV",
    5: "V",
    6: "VI",
    7: "VII",
    8: "VIII"
}

for d in DOMAINS:
    n = d["number"]
    name = d["name"]
    aliases = {
        str(n),
        ROMANS[n],
        f"DOMAIN {n}",
        f"DOMAIN {ROMANS[n]}",
        name.upper(),
        f"DOMAIN {n} - {name}".upper(),
        f"DOMAIN {n} — {name}".upper(),
        f"DOMAIN {ROMANS[n]} - {name}".upper(),
        f"DOMAIN {ROMANS[n]} — {name}".upper()
    }
    for alias in aliases:
        ALIASES[alias.strip().upper()] = name

ALIASES["IDENTITY AND ACCESS MANAGEMENT"] = "Identity and Access Management (IAM)"
ALIASES["IAM"] = "Identity and Access Management (IAM)"


def load_questions(path):
    raw = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(raw, list):
        return raw

    if isinstance(raw, dict):
        if isinstance(raw.get("questions"), list):
            return raw["questions"]

        if isinstance(raw.get("items"), list):
            return raw["items"]

    raise ValueError("JSON must be an array or contain a questions array")


def normalize_domain(value):
    raw = str(value or "").strip()
    upper = re.sub(r"\s+", " ", raw.upper())

    if upper in ALIASES:
        return ALIASES[upper]

    for d in DOMAINS:
        if upper == d["name"].upper():
            return d["name"]

    return None


def question_number(qid):
    m = re.fullmatch(r"CISSP1-(\d{3})", str(qid or "").strip())
    if not m:
        return None
    return int(m.group(1))


errors = []
warnings = []
normalization_notes = []
domain_files = {}
all_source_questions = []

files = sorted(
    p for p in SOURCE.glob("*.json")
    if p.is_file()
)

print("=== SOURCE FILE DISCOVERY ===")
print("JSON source files:", len(files))

for p in files:
    print("SOURCE:", p.name)

if len(files) != 8:
    errors.append(
        f"Expected exactly 8 source JSON files for Exam 01; found {len(files)}"
    )

for path in files:
    print()
    print("AUDITING:", path.name)

    try:
        questions = load_questions(path)
    except Exception as exc:
        errors.append(f"{path.name}: cannot load questions: {exc}")
        continue

    print("Questions:", len(questions))

    if not questions:
        errors.append(f"{path.name}: contains no questions")
        continue

    file_domains = set()

    for i, q in enumerate(questions, start=1):
        if not isinstance(q, dict):
            errors.append(f"{path.name} question {i}: not an object")
            continue

        qid = str(q.get("id", "")).strip()
        num = question_number(qid)

        if num is None:
            errors.append(
                f"{path.name} question {i}: invalid ID '{qid}', expected CISSP1-XXX"
            )

        domain_raw = q.get("domain", q.get("Domain", ""))
        domain = normalize_domain(domain_raw)

        if not domain:
            errors.append(
                f"{path.name} {qid or 'question '+str(i)}: "
                f"unrecognized domain '{domain_raw}'"
            )
        else:
            file_domains.add(domain)

            if str(domain_raw).strip() != domain:
                normalization_notes.append(
                    f"{path.name} {qid}: '{domain_raw}' -> '{domain}'"
                )

        prompt = str(q.get("prompt", "") or "").strip()
        explanation = str(q.get("explanation", "") or "").strip()
        competency = str(q.get("competency", "") or "").strip()
        skill = str(q.get("skill", "") or "").strip()

        if not prompt:
            errors.append(f"{path.name} {qid}: missing prompt")

        if not explanation:
            errors.append(f"{path.name} {qid}: missing explanation")

        if not competency:
            errors.append(f"{path.name} {qid}: missing competency")

        if not skill:
            errors.append(f"{path.name} {qid}: missing skill")

        qtype = str(
            q.get("type", q.get("itemType", ""))
        ).strip().lower()

        if qtype in {"mcq_single", "single", "multiple_choice"}:
            qtype = "mcq"

        if qtype in {"multiselect", "multiple_select"}:
            qtype = "multi_select"

        if qtype not in {"mcq", "multi_select"}:
            errors.append(
                f"{path.name} {qid}: unsupported type '{qtype}'"
            )
            continue

        choices = q.get("choices")

        if not isinstance(choices, dict):
            errors.append(f"{path.name} {qid}: choices must be an object")
            continue

        choice_keys = [
            str(k).strip().upper()
            for k in choices.keys()
        ]

        if len(choice_keys) != len(set(choice_keys)):
            errors.append(f"{path.name} {qid}: duplicate choice keys")

        choice_values = [
            str(v or "").strip()
            for v in choices.values()
        ]

        if any(not v for v in choice_values):
            errors.append(f"{path.name} {qid}: empty choice text")

        normalized_choice_values = [
            re.sub(r"\s+", " ", v).casefold()
            for v in choice_values
        ]

        if len(normalized_choice_values) != len(set(normalized_choice_values)):
            errors.append(f"{path.name} {qid}: duplicate choice text")

        if qtype == "mcq":
            if set(choice_keys) != {"A", "B", "C", "D"}:
                errors.append(
                    f"{path.name} {qid}: MCQ must contain exactly A-D"
                )

            correct = str(q.get("correct", "") or "").strip().upper()

            if not correct:
                errors.append(f"{path.name} {qid}: missing correct answer")
            elif correct not in choice_keys:
                errors.append(
                    f"{path.name} {qid}: correct answer '{correct}' "
                    f"is not a valid choice"
                )

        if qtype == "multi_select":
            answers = q.get("correctAnswers")

            if not isinstance(answers, list):
                errors.append(
                    f"{path.name} {qid}: multi_select requires correctAnswers array"
                )
            else:
                norm_answers = [
                    str(x).strip().upper()
                    for x in answers
                ]

                if len(norm_answers) < 2:
                    errors.append(
                        f"{path.name} {qid}: multi_select must have at least 2 correct answers"
                    )

                if len(norm_answers) != len(set(norm_answers)):
                    errors.append(
                        f"{path.name} {qid}: duplicate entries in correctAnswers"
                    )

                for ans in norm_answers:
                    if ans not in choice_keys:
                        errors.append(
                            f"{path.name} {qid}: correctAnswers contains invalid choice '{ans}'"
                        )

                if len(choice_keys) < 4:
                    errors.append(
                        f"{path.name} {qid}: multi_select has fewer than 4 choices"
                    )

        scenario_flag = q.get("isScenarioBased", False)
        scenario_text = str(q.get("scenarioContext", "") or "").strip()

        scenario_true = (
            scenario_flag is True
            or str(scenario_flag).strip().lower() == "true"
        )

        if scenario_true and not scenario_text:
            errors.append(
                f"{path.name} {qid}: isScenarioBased=true but scenarioContext is empty"
            )

        if not scenario_true and scenario_text:
            errors.append(
                f"{path.name} {qid}: scenarioContext present while isScenarioBased is not true"
            )

    if len(file_domains) != 1:
        errors.append(
            f"{path.name}: expected one domain per source file; "
            f"found {sorted(file_domains)}"
        )
        continue

    domain_name = next(iter(file_domains))

    if domain_name in domain_files:
        errors.append(
            f"Duplicate source file for domain '{domain_name}': "
            f"{domain_files[domain_name].name} and {path.name}"
        )
    else:
        domain_files[domain_name] = path

    d = next(x for x in DOMAINS if x["name"] == domain_name)

    if len(questions) != d["count"]:
        errors.append(
            f"{path.name}: {domain_name} expected {d['count']} questions; "
            f"found {len(questions)}"
        )

    nums = [
        question_number(q.get("id"))
        for q in questions
        if isinstance(q, dict)
    ]

    valid_nums = [n for n in nums if n is not None]
    expected_nums = list(range(d["start"], d["end"] + 1))

    if sorted(valid_nums) != expected_nums:
        errors.append(
            f"{path.name}: ID range for {domain_name} must be "
            f"CISSP1-{d['start']:03d} through CISSP1-{d['end']:03d}"
        )

    all_source_questions.extend(questions)


print()
print("=== DOMAIN FILE MAP ===")

for d in DOMAINS:
    p = domain_files.get(d["name"])
    print(
        f'Domain {d["number"]}: '
        f'{p.name if p else "MISSING"} | '
        f'expected {d["count"]}q | '
        f'CISSP1-{d["start"]:03d} -> CISSP1-{d["end"]:03d}'
    )


print()
print("=== GLOBAL ID AUDIT ===")

ids = [
    str(q.get("id", "")).strip()
    for q in all_source_questions
    if isinstance(q, dict)
]

duplicates = sorted({
    x for x in ids
    if ids.count(x) > 1
})

if duplicates:
    errors.append(
        "Duplicate IDs: " + ", ".join(duplicates)
    )

expected_ids = [
    f"CISSP1-{n:03d}"
    for n in range(1, 151)
]

if sorted(ids) != sorted(expected_ids):
    missing = sorted(set(expected_ids) - set(ids))
    extra = sorted(set(ids) - set(expected_ids))

    if missing:
        errors.append(
            "Missing IDs: " + ", ".join(missing)
        )

    if extra:
        errors.append(
            "Unexpected IDs: " + ", ".join(extra)
        )

print("Total source questions:", len(all_source_questions))
print("Unique IDs:", len(set(ids)))


print()
print("=== NORMALIZATION NOTES ===")

if normalization_notes:
    for note in normalization_notes[:50]:
        print("NOTE:", note)

    if len(normalization_notes) > 50:
        print(
            f"... {len(normalization_notes)-50} additional normalization notes"
        )
else:
    print("None")


print()
print("=== WARNINGS ===")

if warnings:
    for w in warnings:
        print("WARNING:", w)
else:
    print("None")


print()
print("=== ERRORS ===")

if errors:
    for e in errors:
        print("ERROR:", e)

    print()
    print("AUDIT RESULT: BLOCKED")
    print("IMPORT NOT PERFORMED")
    print("PRINTABLES NOT GENERATED")
    sys.exit(2)

print("None")
print()
print("AUDIT RESULT: CLEAN")


def canonicalize_question(q):
    out = dict(q)

    out["id"] = str(q.get("id", "")).strip()

    domain = normalize_domain(
        q.get("domain", q.get("Domain", ""))
    )

    out["domain"] = domain

    if "Domain" in out:
        del out["Domain"]

    raw_type = str(
        q.get("type", q.get("itemType", ""))
    ).strip().lower()

    if raw_type in {"mcq_single", "single", "multiple_choice"}:
        raw_type = "mcq"

    if raw_type in {"multiselect", "multiple_select"}:
        raw_type = "multi_select"

    out["type"] = raw_type

    if "itemType" in out:
        del out["itemType"]

    choices = {}

    for k, v in q.get("choices", {}).items():
        choices[str(k).strip().upper()] = v

    out["choices"] = choices

    if raw_type == "mcq":
        out["correct"] = str(
            q.get("correct", "")
        ).strip().upper()

        out.pop("correctAnswers", None)

    if raw_type == "multi_select":
        out["correctAnswers"] = sorted([
            str(x).strip().upper()
            for x in q.get("correctAnswers", [])
        ])

        out.pop("correct", None)

    scenario_text = str(
        q.get("scenarioContext", "") or ""
    ).strip()

    scenario_true = (
        q.get("isScenarioBased") is True
        or str(q.get("isScenarioBased", "")).strip().lower() == "true"
    )

    out["isScenarioBased"] = bool(scenario_true)

    if scenario_true:
        out["scenarioContext"] = scenario_text
    else:
        out.pop("scenarioContext", None)

    return out


master = []

domain_questions = {}

for d in DOMAINS:
    p = domain_files[d["name"]]
    qs = load_questions(p)
    qs = [canonicalize_question(q) for q in qs]
    qs.sort(key=lambda q: question_number(q["id"]))

    domain_questions[d["number"]] = qs
    master.extend(qs)

master.sort(key=lambda q: question_number(q["id"]))

DATA.mkdir(parents=True, exist_ok=True)
PDF.mkdir(parents=True, exist_ok=True)

master_path = DATA / "cissp_exam_01.json"

master_payload = {
    "examId": "cissp",
    "examNumber": 1,
    "title": "CISSP Full-Length Practice Exam 01",
    "questions": master
}

master_path.write_text(
    json.dumps(
        master_payload,
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


def clean_pdf_text(value):
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
    text = clean_pdf_text(text)

    result = []

    for paragraph in text.splitlines() or [""]:
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


def pdf_escape(s):
    return (
        clean_pdf_text(s)
        .replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )


def make_pdf(path, title, domain_number, questions):
    pages = []
    current = []

    max_lines = 53

    def push(line="", bold=False, size=10):
        nonlocal current

        if len(current) >= max_lines:
            pages.append(current)
            current = []

        current.append(
            (clean_pdf_text(line), bold, size)
        )

    def wrapped(text, indent="", bold=False, size=10, width=92):
        lines = wrap_lines(text, width=width)

        for line in lines:
            push(indent + line, bold=bold, size=size)

    push(title, True, 14)
    push(f"Domain {domain_number}", True, 11)
    push("")
    push(
        "Choose the best answer for each question. "
        "For multi-select items, select all required answers.",
        False,
        9
    )
    push("")

    for local_no, q in enumerate(questions, start=1):
        push(
            f"Question {local_no} ({q['id']})",
            True,
            10
        )

        if q.get("isScenarioBased") and q.get("scenarioContext"):
            wrapped(
                "Scenario: " + q["scenarioContext"],
                size=9
            )
            push("")

        wrapped(
            q.get("prompt", ""),
            size=10
        )

        for letter in sorted(q.get("choices", {})):
            wrapped(
                f"{letter}. {q['choices'][letter]}",
                indent="   ",
                size=9,
                width=86
            )

        push("")

    if current:
        pages.append(current)
        current = []

    push("ANSWER KEY AND EXPLANATIONS", True, 14)
    push("")

    for local_no, q in enumerate(questions, start=1):
        if q.get("type") == "multi_select":
            correct = ", ".join(
                q.get("correctAnswers", [])
            )
        else:
            correct = q.get("correct", "")

        push(
            f"Question {local_no} ({q['id']}) — Correct: {correct}",
            True,
            10
        )

        wrapped(
            q.get("explanation", ""),
            size=9
        )

        push("")

    if current:
        pages.append(current)

    objects = []

    def obj(data):
        objects.append(data)
        return len(objects)

    font_regular = obj(
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
        b"/Encoding /WinAnsiEncoding >>"
    )

    font_bold = obj(
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
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

        for line, bold, size in page:
            font = "F2" if bold else "F1"

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

        stream = "\n".join(commands).encode(
            "cp1252",
            errors="replace"
        )

        content = (
            f"<< /Length {len(stream)} >>\nstream\n".encode()
            + stream
            + b"\nendstream"
        )

        content_id = obj(content)
        content_ids.append(content_id)

        page_id = obj(b"")
        page_ids.append(page_id)

    pages_id = obj(b"")

    for idx, page_id in enumerate(page_ids):
        objects[page_id - 1] = (
            f"<< /Type /Page /Parent {pages_id} 0 R "
            f"/MediaBox [0 0 612 792] "
            f"/Resources << /Font << "
            f"/F1 {font_regular} 0 R "
            f"/F2 {font_bold} 0 R "
            f">> >> "
            f"/Contents {content_ids[idx]} 0 R >>"
        ).encode()

    kids = " ".join(
        f"{pid} 0 R"
        for pid in page_ids
    )

    objects[pages_id - 1] = (
        f"<< /Type /Pages /Kids [{kids}] "
        f"/Count {len(page_ids)} >>"
    ).encode()

    catalog_id = obj(
        f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode()
    )

    data = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]

    for i, body in enumerate(objects, start=1):
        offsets.append(len(data))
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

    for off in offsets[1:]:
        data.extend(
            f"{off:010d} 00000 n \n".encode()
        )

    data.extend(
        (
            f"trailer\n<< /Size {len(objects)+1} "
            f"/Root {catalog_id} 0 R >>\n"
            f"startxref\n{xref}\n%%EOF\n"
        ).encode()
    )

    path.write_bytes(data)


print()
print("=== GENERATING PRINTABLE PDFs 01-08 ===")

printables = []

for d in DOMAINS:
    pdf_no = d["pdf"]

    filename = f"cissp_printable_exam_{pdf_no:02d}.pdf"
    path = PDF / filename

    label = (
        f"CISSP Printable Practice Exam {pdf_no:02d} — "
        f"Domain {d['number']} — {d['name']}"
    )

    make_pdf(
        path,
        label,
        d["number"],
        domain_questions[d["number"]]
    )

    print(
        f"CREATED: {filename} | "
        f"Domain {d['number']} | "
        f"{len(domain_questions[d['number']])} questions"
    )

    printables.append({
        "label": label,
        "file": filename
    })


cfg = json.loads(
    CONFIG.read_text(encoding="utf-8")
)

exam_file = "cissp_exam_01.json"

cfg["examFiles"] = [exam_file]

for section in cfg["sections"]:
    section["examFiles"] = [exam_file]

cfg["printables"] = printables

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
print("examFiles:", cfg["examFiles"])
print("printables:", len(cfg["printables"]))

for p in cfg["printables"]:
    print(
        p["file"],
        "|",
        p["label"]
    )


print()
print("=== POST-IMPORT MASTER AUDIT ===")

master_check = json.loads(
    master_path.read_text(encoding="utf-8")
)

questions = master_check["questions"]

post_errors = []

if len(questions) != 150:
    post_errors.append(
        f"Master contains {len(questions)} questions instead of 150"
    )

master_ids = [
    q["id"]
    for q in questions
]

if master_ids != expected_ids:
    post_errors.append(
        "Master ID order is not CISSP1-001 through CISSP1-150"
    )

for d in DOMAINS:
    count = sum(
        1
        for q in questions
        if q.get("domain") == d["name"]
    )

    print(
        f'Domain {d["number"]}: '
        f'{count}/{d["count"]}'
    )

    if count != d["count"]:
        post_errors.append(
            f"Master domain {d['number']} count mismatch"
        )

if post_errors:
    for e in post_errors:
        print("ERROR:", e)

    print("POST-IMPORT AUDIT: PROBLEM")
    sys.exit(3)

print("Total: 150/150")
print("IDs: CISSP1-001 -> CISSP1-150")
print("POST-IMPORT AUDIT: CLEAN")
