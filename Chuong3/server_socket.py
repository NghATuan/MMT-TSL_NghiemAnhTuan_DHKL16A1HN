import socket  # Thư viện tích hợp sẵn trong Python để tạo socket (TCP/UDP)

HOST = 'localhost'  # Địa chỉ IP máy chủ
                    # (ở đây dùng localhost để chạy trên cùng máy)

PORT = 12345        # Cổng giao tiếp mà server sẽ lắng nghe kết nối

# Tạo socket sử dụng giao thức TCP (SOCK_STREAM)
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Gán socket vào địa chỉ IP và cổng đã khai báo
server_socket.bind((HOST, PORT))

# Đặt socket ở trạng thái lắng nghe kết nối từ client
server_socket.listen()

print(f"Server đang lắng nghe tại {HOST}:{PORT}...")

# Chấp nhận kết nối từ client (hàm này sẽ chờ đến khi có client gửi đến)
conn, addr = server_socket.accept()
print(f"Kết nối từ {addr}")  # In ra địa chỉ IP của client

# Vòng lặp nhận dữ liệu từ client liên tục
while True:
    data = conn.recv(1024)  # Nhận tối đa 1024 byte dữ liệu
    if not data:
        break  # Nếu client ngắt kết nối thì dừng vòng lặp
    
    # Hiển thị dữ liệu nhận được
    print(f"[SERVER] Nhận dữ liệu: {data.decode()}")

# Đóng kết nối với client và socket chính
conn.close()
server_socket.close()