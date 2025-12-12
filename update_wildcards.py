#!/usr/bin/env python3
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, Set, Tuple, Optional, List

import requests
from publicsuffix2 import PublicSuffixList

# Các nguồn wildcard
INSCOPE_URLS = [
    "https://raw.githubusercontent.com/rix4uni/scope/refs/heads/main/data/Wildcards/inscope_wildcards.txt",
    "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/refs/heads/main/data/wildcards.txt",
]

# Public suffix list để:
# - Tính eTLD+1 (public suffix)
# - Brute các pattern dạng foo.* / *.foo.*
PUBLIC_SUFFIX_URL = "https://publicsuffix.org/list/public_suffix_list.dat"

OUTPUT_PATH = "wildcards.txt"


def fetch(url: str) -> str:
    resp = requests.get(url, timeout=60)
    resp.raise_for_status()
    return resp.text


def parse_targets(text: str) -> Set[str]:
    """
    Hai file raw có thể là 1 dòng dài hoặc nhiều dòng.
    Cứ split theo whitespace là an toàn.
    """
    items: Set[str] = set()
    for token in text.split():
        token = token.strip()
        if not token or token.startswith("#"):
            continue
        items.add(token)
    return items


def fetch_public_suffix_data() -> Tuple[PublicSuffixList, List[str]]:
    """
    Tải public_suffix_list.dat, bỏ comment // và dòng trống,
    đồng thời dùng chính dữ liệu này cho:
    - PublicSuffixList (tính eTLD+1)
    - List suffix để brute các pattern kiểu foo.*
    """
    txt = fetch(PUBLIC_SUFFIX_URL)

    cleaned_lines: List[str] = []
    for line in txt.splitlines():
        line = line.strip()
        # Bỏ dòng trống & dòng comment // ...
        if not line or line.startswith("//"):
            continue
        cleaned_lines.append(line)

    # PublicSuffixList chấp nhận list các dòng PSL
    psl = PublicSuffixList(cleaned_lines)
    return psl, cleaned_lines


def normalize_host(
    raw: str, psl: PublicSuffixList
) -> Tuple[Optional[str], bool, Optional[str]]:
    """
    Trả về (base_domain, is_fuzzy_suffix, fuzzy_prefix)

    - base_domain: domain đã chuẩn hoá (không có *), ví dụ:
        *-prod.arlo.com             -> arlo.com
        *.stadtwien.onmicrosoft.com -> stadtwien.onmicrosoft.com
        *eua.cms.gov                -> cms.gov  (lấy eTLD+1)
    - is_fuzzy_suffix: True nếu là dạng foo.* / *.foo.*
      (cần brute suffix)
    - fuzzy_prefix: 'askteamclean' trong '*.askteamclean.*' chẳng hạn.
    """
    h = raw.strip()
    if not h or h.startswith("#"):
        return None, False, None

    # Bỏ scheme nếu lỡ có: http(s)://
    if h.startswith("http://") or h.startswith("https://"):
        h = h.split("://", 1)[1]

    # Bỏ path / query
    h = h.split("/", 1)[0]
    # Bỏ port
    h = h.split(":", 1)[0]

    fuzzy = False
    # Pattern kiểu foo.* hoặc *.foo.*
    if h.endswith(".*"):
        fuzzy = True
        h = h[:-2]  # cắt bỏ '.*'
        if h.endswith("."):
            h = h[:-1]

    # Bỏ các wildcard ở đầu: *, *., *- ...
    while h.startswith("*"):
        h = h[1:]
        if h.startswith("."):
            h = h[1:]

    # Bỏ ký tự thừa đầu nếu còn
    h = h.lstrip("-.")
    if not h:
        return None, fuzzy, None

    h = h.lower()

    if fuzzy:
        # ví dụ từ '*.askteamclean.*' => prefix = 'askteamclean'
        # hoặc 'cdn.askteamclean', v.v.
        return None, True, h

    # Lấy registrable domain (eTLD+1) từ public suffix list
    try:
        base = psl.get_public_suffix(h)
    except Exception:
        base = h

    return base.lower(), False, None


def expand_fuzzy(prefix: str, suffix_lines: Iterable[str]) -> Set[str]:
    """
    Từ prefix (vd: 'askteamclean'),
    duyệt qua toàn bộ public suffix list (đã bỏ comment),
    ghép prefix.suffix, resolve DNS, nếu tồn tại thì giữ lại.

    Chạy song song bằng ThreadPoolExecutor để nhanh hơn.
    """
    candidates: List[str] = []

    for raw_suffix in suffix_lines:
        # xử lý wildcard/exception trong PSL: *.ck, !city.kawasaki.jp, ...
        suf = raw_suffix.lstrip("*.!")
        if not suf:
            continue
        candidates.append(f"{prefix}.{suf}")

    results: Set[str] = set()

    def check_domain(domain: str) -> Optional[str]:
        try:
            socket.getaddrinfo(domain, 80)
            return domain.lower()
        except Exception:
            return None

    # Số worker tuỳ bạn, 50–100 là hợp lý cho GH Actions
    max_workers = min(100, max(10, len(candidates) // 50 or 10))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {
            executor.submit(check_domain, d): d for d in candidates
        }
        for future in as_completed(future_to_domain):
            dom = future.result()
            if dom:
                results.add(dom)

    return results


def main() -> None:
    # Đặt timeout cho mọi DNS lookup để tránh treo
    socket.setdefaulttimeout(1.0)

    print("[*] Downloading wildcard sources...")
    raw_items: Set[str] = set()
    for url in INSCOPE_URLS:
        print(f"    - {url}")
        txt = fetch(url)
        raw_items |= parse_targets(txt)

    print(f"[*] Loaded {len(raw_items)} raw entries")

    print("[*] Downloading public suffix list for normalization & fuzzy expansion...")
    psl, suffix_lines = fetch_public_suffix_data()

    normalized: Set[str] = set()
    fuzzy_prefixes: Set[str] = set()

    for raw in raw_items:
        base, is_fuzzy, prefix = normalize_host(raw, psl)
        if base:
            normalized.add(base)
        if is_fuzzy and prefix:
            fuzzy_prefixes.add(prefix)

    if fuzzy_prefixes:
        print(
            f"[*] Found {len(fuzzy_prefixes)} fuzzy prefix(es): "
            + ", ".join(sorted(fuzzy_prefixes))
        )
    else:
        print("[*] No fuzzy suffix patterns found")

    # Expand các pattern dạng foo.* / *.foo.*
    for prefix in sorted(fuzzy_prefixes):
        print(f"[*] Expanding fuzzy prefix: {prefix}.*")
        expanded = expand_fuzzy(prefix, suffix_lines)
        print(f"    -> {len(expanded)} valid domain(s)")
        normalized |= expanded

    # Sort & ghi file
    cleaned = sorted(normalized)
    print(f"[*] Writing {len(cleaned)} normalized entries to {OUTPUT_PATH}")
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        for item in cleaned:
            f.write(item + "\n")


if __name__ == "__main__":
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write("test)
