from urllib.parse import urlparse


def build_site_tree(urls: list) -> dict:
    tree = {}
    for url in urls:
        parsed = urlparse(url)

        # 1. Lấy đường dẫn gốc
        path_parts = [p for p in parsed.path.split('/') if p]

        # 2. [MỚI] Lấy đường dẫn SPA (Fragment)
        if parsed.fragment:
            # Thêm ký hiệu '#' làm một node thư mục ảo để dễ nhìn trên UI
            path_parts.append('#')
            fragment_parts = [p for p in parsed.fragment.split('/') if p]
            path_parts.extend(fragment_parts)

        # 3. Xây dựng cây
        current_level = tree
        for part in path_parts:
            if part not in current_level:
                current_level[part] = {}
            current_level = current_level[part]

    return tree