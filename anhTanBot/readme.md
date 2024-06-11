# Chức năng chính

Số lượng hiện tại: 4

## Điểm danh

### Cấu hình file điểm danh

- file danhsachlop.xlsx được mặc định là file điểm danh
- trong đó sheet 1 dùng để quản lý

### Sử dụng
```
/diem_danh
```

### Input
Chỉ cần gõ lệnh ở kênh muốn điểm danh

### Output
1. Chương trình sẽ điểm danh 5p/ lần. in ra danh sách học viên vắng và có mặt
2. Chương trình sẽ không dừng lại nếu còn học viên vắng mặt. Để dừng điểm danh --> xem phần chức năng "Dừng điểm danh"
3. <strong>Lưu ý: Sau 200 giây, tin nhắn của bot sẽ tự động xóa. </strong> 


Kết quả sẽ hiển thị như sau: 

Có mặt: <br> 
- cheaterdxd

Chưa có mặt: <br>
- lethanhtuan
- anhTan
- meme


## Dừng điểm danh

Câu lệnh được dùng để dừng điểm danh
```
/dung_diem_danh
```

# Gán role cho mọi user trong Voice chat

Câu lệnh được dùng để gán Role cho mọi user đang tham gia kênh Voice Chat (CHỈ VOICE CHAT)

```
role_set_all [tên role muốn gán]
```

# Gán role cho một số user

Câu lệnh được dùng để gán Role cho một hoặc một số user (KHÔNG HẠN CHẾ CÓ ON/OFF, tham gia hay không tham gia chat voice)

```
role_set_for [tên user muốn gán] [tên role muốn gán]

+ tên user muốn gán: có thể là 1 list các user, phân biệt nhau bằng dấu "," ví dụ: tuấn,tân,tod
```


