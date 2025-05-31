import socket

# Thiết lập server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("127.0.0.1", 5000))  # Lắng nghe trên IP và cổng 80
server_socket.listen(5)  # Cho phép tối đa 5 kết nối đang chờ

print("Server đang lắng nghe kết nối...")

while True:
    client_socket, client_address = server_socket.accept()
    print(f"Kết nối từ {client_address}")

    # Nhận dữ liệu từ client
    data = client_socket.recv(1025).decode()
    print(f"Dữ liệu nhận được: {data}")

    # Phản hồi client
    response = "Server đã nhận dữ liệu!"
    client_socket.send(response.encode())

    # Đóng kết nối
    client_socket.close()

    # Điều kiện dừng server khi nhận "exit" từ client
    if data.lower() == "exit":
        print("Server đang tắt...")
        break

server_socket.close()