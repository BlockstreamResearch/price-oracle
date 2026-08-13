import html
import json
import os
import sys
import urllib.error
import urllib.request


API_URL = "https://api.openai.com/v1/responses"
REPORT_PATH = os.environ.get("SECURITY_REVIEW_REPORT", "security-review.md")


def write_report(content):
    with open(REPORT_PATH, "w", encoding="utf-8") as report:
        report.write(content.rstrip())
        report.write("\n")


def markdown_text(value):
    text = html.escape(str(value), quote=False).replace("@", "&#64;")
    for character in "\\`*_{}[]()#+-.!|>":
        text = text.replace(character, f"\\{character}")
    return text.replace("\n", "<br>")


def fail(message):
    print(message)
    write_report(f"## AI security review\n\nReview failed: {markdown_text(message)}")
    sys.exit(1)

api_key = os.environ["OPENAI_API_KEY"]

with open("pr.diff", "r", encoding="utf-8") as f:
    diff = f.read()

# Avoid accidentally sending enormous PRs and spending lots of money.
MAX_DIFF_SIZE = 100_000

if len(diff) > MAX_DIFF_SIZE:
    fail(
        f"PR diff is too large ({len(diff)} bytes); "
        f"the maximum is {MAX_DIFF_SIZE} bytes."
    )

if not diff.strip():
    print("No diff found.")
    write_report("## AI security review\n\nNo diff found.")
    sys.exit(0)


prompt = f"""
You are a senior application security engineer reviewing a GitHub pull request.

Analyze ONLY the code changes in the supplied diff.

Your job is to identify genuine security vulnerabilities.

IMPORTANT:
- Report ONLY HIGH or CRITICAL vulnerabilities.
- Ignore LOW and MEDIUM issues.
- Ignore style issues.
- Ignore maintainability issues.
- Ignore generic best-practice recommendations.
- Ignore theoretical vulnerabilities without a realistic attack path.
- Be conservative.
- Do not invent vulnerabilities.
- A finding must have a concrete security impact and plausible exploitation path.

Look for issues such as:
- authentication bypass
- authorization bypass
- SQL/NoSQL injection
- command injection
- path traversal
- SSRF
- XSS
- insecure deserialization
- arbitrary code execution
- privilege escalation
- sensitive information exposure
- cryptographic failures
- insecure secret handling
- dangerous file operations
- other vulnerabilities with HIGH or CRITICAL impact

Return JSON with exactly this structure:

{{
  "findings": [
    {{
      "severity": "HIGH or CRITICAL",
      "title": "Short title",
      "file": "path/to/file",
      "line": 123,
      "cwe": "CWE-XXX",
      "description": "Why this is vulnerable.",
      "attack_scenario": "How an attacker could exploit it.",
      "recommendation": "How to fix it."
    }}
  ]
}}

If there are no genuine HIGH or CRITICAL vulnerabilities, return:

{{"findings": []}}

Do not report medium or low severity issues.

PR diff:
----------------
{diff}
----------------
"""


payload = {
    "model": "gpt-5-mini",
    "input": prompt,
    "text": {
        "format": {
            "type": "json_schema",
            "name": "security_review",
            "strict": True,
            "schema": {
                "type": "object",
                "properties": {
                    "findings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "severity": {
                                    "type": "string",
                                    "enum": ["HIGH", "CRITICAL"],
                                },
                                "title": {"type": "string"},
                                "file": {"type": "string"},
                                "line": {"type": "integer"},
                                "cwe": {"type": "string"},
                                "description": {"type": "string"},
                                "attack_scenario": {"type": "string"},
                                "recommendation": {"type": "string"},
                            },
                            "required": [
                                "severity",
                                "title",
                                "file",
                                "line",
                                "cwe",
                                "description",
                                "attack_scenario",
                                "recommendation",
                            ],
                            "additionalProperties": False,
                        },
                    }
                },
                "required": ["findings"],
                "additionalProperties": False,
            },
        }
    },
}


request = urllib.request.Request(
    API_URL,
    data=json.dumps(payload).encode("utf-8"),
    headers={
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    },
    method="POST",
)

try:
    with urllib.request.urlopen(request) as response:
        result = json.loads(response.read())

except (urllib.error.URLError, json.JSONDecodeError) as e:
    fail(f"OpenAI API request failed: {e}")


# Extract the structured output.
output_text = result.get("output", [])

findings = None

for item in output_text:
    if item.get("type") != "message":
        continue

    for content in item.get("content", []):
        if content.get("type") == "output_text":
            try:
                parsed = json.loads(content["text"])
                findings = parsed.get("findings", [])
            except json.JSONDecodeError:
                pass

if findings is None:
    fail("Could not parse the security review result.")


if not findings:
    message = "No HIGH or CRITICAL vulnerabilities found."
    print(message)
    write_report(f"## AI security review\n\n{message}")
    sys.exit(0)


report = ["## AI security review", "", "**HIGH / CRITICAL findings detected**", ""]

for finding in findings:
    severity = markdown_text(finding["severity"])
    title = markdown_text(finding["title"])
    file = markdown_text(finding["file"])
    line = finding["line"]
    cwe = markdown_text(finding["cwe"])
    description = markdown_text(finding["description"])
    attack_scenario = markdown_text(finding["attack_scenario"])
    recommendation = markdown_text(finding["recommendation"])

    report.extend(
        [
            f"### {severity}: {title}",
            "",
            f"**Location:** `{file}:{line}`  ",
            f"**CWE:** `{cwe}`",
            "",
            description,
            "",
            f"**Attack scenario:** {attack_scenario}",
            "",
            f"**Recommendation:** {recommendation}",
            "",
        ]
    )

write_report("\n".join(report))
print(f"Found {len(findings)} HIGH or CRITICAL security issue(s).")

# Any HIGH/CRITICAL finding fails the job.
sys.exit(1)