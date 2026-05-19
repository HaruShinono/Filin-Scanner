# utils/tree_builder.py
from urllib.parse import urlparse
def build_site_tree(urls: list) -> dict:
    """
    Chuyển list ['http://site.com/a/b', 'http://site.com/a/c']
    thành dạng cây lồng nhau.
    """
    tree = {}
    for url in urls:
        parsed = urlparse(url)
        # Tách path thành các thư mục, loại bỏ các thành phần rỗng
        path_parts = [p for p in parsed.path.split('/') if p]

        current_level = tree
        for part in path_parts:
            if part not in current_level:
                current_level[part] = {}
            current_level = current_level[part]

    return tree