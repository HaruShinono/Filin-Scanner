from urllib.parse import urlparse


def build_site_tree(urls: list) -> dict:
    tree = {}
    for url in urls:
        parsed = urlparse(url)
        path = parsed.path
        parts = [p for p in path.split('/') if p]

        current_level = tree
        for part in parts:
            if part not in current_level:
                current_level[part] = {}
            current_level = current_level[part]

    return tree