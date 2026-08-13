import json
import os
import sys
import urllib.request


API_URL = "https://api.openai.com/v1/responses"

api_key = os.environ["OPENAI_API_KEY"]
pr_number = os.environ["PR_NUMBER"]

with open("pr.diff", "r", encoding="utf-8") as f:
    diff = f.read()

# Avoid accidentally sending enormous PRs and spending lots of money.
MAX_DIFF_SIZE = 100_000

if len(diff) > MAX_DIFF_SIZE:
    print(f"PR diff is too large ({len(diff)} bytes).")
    print(f"Maximum allowed size is {MAX_DIFF_SIZE} bytes.")
    sys.exit(1)

if not diff.strip():
    print("No diff found.")
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

except Exception as e:
    print(f"OpenAI API request failed: {e}")
    sys.exit(1)


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
    print("Could not parse security review result.")
    sys.exit(1)


if not findings:
    print("✅ No HIGH or CRITICAL vulnerabilities found.")
    sys.exit(0)


print()
print("🚨 HIGH / CRITICAL SECURITY FINDINGS")
print()

for finding in findings:
    print(f"[{finding['severity']}] {finding['title']}")
    print(f"File: {finding['file']}:{finding['line']}")
    print(f"CWE: {finding['cwe']}")
    print()
    print(finding["description"])
    print()
    print(f"Attack scenario: {finding['attack_scenario']}")
    print()
    print(f"Recommendation: {finding['recommendation']}")
    print()
    print("-" * 80)

# Any HIGH/CRITICAL finding fails the job.
sys.exit(1)