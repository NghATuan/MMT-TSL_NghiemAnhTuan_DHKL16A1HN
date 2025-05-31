import socket       # Thư viện dùng để tạo socket
import time         # Thư viện để tạo khoảng dừng (sleep)
import random       # Thư viện để tạo số ngẫu nhiên (giả lập nhiệt độ)

HOST = 'localhost'  # Địa chỉ IP của server (ở đây là cùng máy)
PORT = 12345        # Cổng giao tiếp giống với server

# Tạo socket TCP
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Kết nối đến server
client_socket.connect((HOST, PORT))

# Vòng lặp gửi dữ liệu 10 lần
for i in range(10):
    # Tạo nhiệt độ ngẫu nhiên từ 25.0-35.0°C
    temp = round(random.uniform(25.0, 35.0), 2)
    message = f"Nhiệt độ: {temp}°C"  # Định dạng chuỗi tin nhắn

    # Gửi dữ liệu dạng byte đến server
    client_socket.sendall(message.encode())
    
    print(f"[CLIENT] Gửi: {message}")  # In thông báo gửi dữ liệu
    
    # Dừng 2 giây trước khi gửi lần tiếp theo
    time.sleep(2)

# Đóng kết nối sau khi gửi xong
client_socket.close()