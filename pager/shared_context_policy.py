import re


BLOCKED_CONTEXT_RE = re.compile(
    r"(?:private[_\s-]*local-llm|私有.{0,8}local-llm|local-llm\s*/\s*h3|"
    r"local-llm(?!3[-_]embedding).{0,100}(?:memory-service|权限|隐私|红线|隔离|污染|shared|记忆池|工作区|产物|独占)|"
    r"(?:memory-service|权限|隐私|红线|隔离|污染|shared|记忆池|工作区|产物|独占).{0,100}local-llm(?!3[-_]embedding))",
    re.IGNORECASE | re.DOTALL,
)


def blocked_context(*texts):
    return any(BLOCKED_CONTEXT_RE.search(str(text or '')) for text in texts)


def public_text(text):
    text = str(text or '')
    spans = [(match.start(), match.end()) for match in BLOCKED_CONTEXT_RE.finditer(text)]
    offset = 0
    kept = []
    for line in text.splitlines(keepends=True):
        end = offset + len(line)
        if not any(start < end and stop > offset for start, stop in spans):
            kept.append(line)
        offset = end
    return ''.join(kept)
