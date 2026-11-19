"""The single-file page: every element its script looks up must exist, and every menu entry must open a page."""
import re
from pathlib import Path

HTML = (Path(__file__).resolve().parents[1] / "src" / "cspm_collector" / "web" / "static" / "index.html").read_text(encoding="utf-8")
SCRIPT = HTML[HTML.index("<script>"):]
MARKUP = HTML[:HTML.index("<script>")]

# ids that the script builds itself (so they are not in the markup)
BUILT_BY_SCRIPT = {"c_total", "c_per_account", "c_per_service", "c_per_resource"}


def test_every_element_the_script_looks_up_exists_in_the_markup():
    wanted = set(re.findall(r'\$\("([A-Za-z0-9_-]+)"\)', SCRIPT))
    present = set(re.findall(r'\bid="([A-Za-z0-9_-]+)"', MARKUP))
    missing = sorted(wanted - present - BUILT_BY_SCRIPT)
    assert not missing, f"the script uses ids that are not in the page: {missing}"


def test_element_ids_are_unique():
    ids = re.findall(r'\bid="([A-Za-z0-9_-]+)"', MARKUP)
    dup = sorted({i for i in ids if ids.count(i) > 1})
    assert not dup, f"duplicate ids: {dup}"


def test_every_menu_entry_has_a_page_and_a_title_and_every_page_a_menu_entry():
    nav = set(re.findall(r'<a href="#/([a-z-]+)" data-page="\1"', MARKUP))
    pages = set(re.findall(r'<section class="page" data-page="([a-z-]+)"', MARKUP))
    titles = set(re.findall(r'(?:^|[{,\s])"?([a-z-]+)"?: "[^"]+"', SCRIPT[SCRIPT.index("const PAGE_TITLES"):SCRIPT.index("function showPage")]))
    assert nav == pages, (nav ^ pages)
    assert pages <= titles, (pages - titles)
    assert "dashboard" in pages


def test_menu_groups_keep_similar_entries_together():
    groups = re.findall(r"<h6>([^<]+)</h6>((?:\s*<a [^>]*>.*?</a>)+)", MARKUP, flags=re.S)
    layout = {name: re.findall(r'data-page="([a-z-]+)"', block) for name, block in groups}
    assert layout == {"수집": ["items", "akamai", "item-groups", "history", "changes", "health"], "어카운트": ["accounts", "account-groups"],
                      "시스템": ["settings", "audit"]}


def test_page_and_server_agree_on_the_api_level():
    from cspm_collector.web.app import API_LEVEL
    assert re.search(rf"const NEED_API = {API_LEVEL};", SCRIPT), "bump NEED_API in index.html together with API_LEVEL"
    assert 'id="staleBanner"' in MARKUP
