import pyshark
path = r"NguyenBaDuyAnh_NghiemAnhTuan.pcapng"
cap = pyshark.FileCapture(path, display_filter='http.request')
print('Phân tích gói HTTP REQUEST chứa từ khóa "login" hoặc "test":\n')

for i, pkt in enumerate(cap):
    try:
        http_info = str(pkt.http).lower()

        if 'login' in http_info or test in http_info:
            print('='*50)
            print(f'Gói #{i+1} có chứa từ khóa')

            # Hiển thị thời gian bắt được gói tín
            print('Thời gian:', pkt.sniff_time)

            # Hiển thị IP nguồn (máy gửi request) và IP đích (máy chủ) 
            print("IP nguồn:", pkt.ip.src if hasattr(pkt, 'ip') else 'N/A')
            print("IP đích:", pkt.ip.dst if hasattr(pkt, 'ip') else 'N/A')

            # Hiển thị phương thức HTTP: GET hoặc POST
            if hasattr(pkt.http, "request_method"):
                print("Phương thức:", pkt.http.request_method)
            # Hiển thị URL đầy đủ nếu có
            if hasattr(pkt.http, 'host') and hasattr(pkt.http, 'request_uri'):
                print("URL", f"http://(pkt.http.host) (pkt.http.request_uri)")
            # Hiển thị Cookie nếu gói có gửi cookie
            if hasattr(pkt.http, 'cookie'):
                print("Cookie:", pkt.http.cookie)
            # Hiển thị dữ liệu gửi đi trong phần thân (POST form data)
            if hasattr(pkt.http, 'file_data'):
                print("Payload:", pkt.http.file_data)

    # Nếu có lỗi (ví dụ gói tin không có lớp http), thì tiếp tục gói sau
    except Exception as e:
        print(f" [Lỗi tại gói #{1+1}]: (e)")

print("Nhận xét: Gói tin HTTP sử dụng phương thức POST và truyền dữ liệu đăng nhập ở tầng ứng dụng dưới dạng văn bản rõ (plaintext), có thể quan sát trực tiếp trong payload.")