# Chức năng chính

Số lượng hiện tại: 2

## Điểm danh

### Sử dụng
```
/diem-danh
```

### Input
1. File txt với tên là tên của kênh cần điểm danh. File này phải đặt cùng thư mục với ứng dụng
2. Bên trong file chứa danh sách học viên, mỗi dòng 1 người, tên học viên là tên hiển thị trên discord của họ
vd: 
- Điểm danh ở kênh: sieu-ly-mau-giao
-> file: sieu-ly-mau-giao.txt
-> trong file: 
```
cheaterdxd
Tân
Tod
```
- Nếu tên kênh là tiếng việt thì đặt tiếng việt, siêu-lý-mẫu-giáo.txt

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
/dung-diem-danh
```

