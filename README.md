# README.md

# Web Vulnerability Scanner with Web UI

Một công cụ quét lỗ hổng web được xây dựng bằng Python và Flask, cung cấp một giao diện người dùng local trực quan để quản lý và xem kết quả các phiên quét, tương tự như Nessus.

## Tính năng Chính

-   **Giao diện Web Local:** Quản lý mọi thứ qua trình duyệt tại `http://127.0.0.1:5000`.
-   **Quét Bất đồng bộ:** Chạy các phiên quét nặng trong nền mà không làm treo giao diện.
-   **Cập nhật Real-time:** Xem tiến độ và kết quả lỗ hổng được cập nhật trực tiếp không cần refresh.
-   **Kiến trúc Module hóa:** Dễ dàng thêm hoặc chỉnh sửa các module quét lỗ hổng mới.
-   **Cấu hình Tập trung:** Toàn bộ payload và cấu hình được quản lý trong file YAML.
-   **Lưu trữ Lịch sử:** Mọi kết quả quét được lưu vào database SQLite để xem lại sau.

## Cài đặt

1.  **Clone repository:**
    ```bash
    git clone https://your-repository-url.com/web-scanner.git
    cd web-scanner
    ```

2.  **Tạo và kích hoạt môi trường ảo (khuyến khích):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # Trên Windows: venv\Scripts\activate
    ```

3.  **Cài đặt các thư viện cần thiết:**
    ```bash
    pip install -r requirements.txt
    ```
    *(Đối với Selenium, bạn cũng cần cài đặt Google Chrome và ChromeDriver tương ứng với phiên bản Chrome của bạn và đảm bảo nó nằm trong PATH.)*

## Sử dụng

1.  **Chạy ứng dụng web:**
    ```bash
    flask run
    ```
    *(Hoặc `python app.py` nếu bạn đã cấu hình)*

2.  **Mở trình duyệt:**
    Truy cập địa chỉ [http://127.0.0.1:5000](http://127.0.0.1:5000).

3.  **Bắt đầu Quét:**
    -   Nhập URL mục tiêu vào form "New Scan".
    -   Nhấn "Start Scan".
    -   Bạn sẽ được chuyển đến trang chi tiết để theo dõi tiến trình.
