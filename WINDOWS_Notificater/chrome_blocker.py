import psutil
from plyer import notification
import time

# Hàm gửi thông báo
def send_notification():
    notification.notify(
        title='Chrome Notification',
        message='Chrome process has been opened!',
    )

# Hàm kiểm tra xem chrome.exe có đang chạy hay không
def check_chrome():
    for proc in psutil.process_iter(['pid', 'name']):
        if "chrome.exe" in proc.info['name']:
            print(proc)
            return True
    return False

# Hàm theo dõi
def monitor_chrome():
    # while True:
    if check_chrome():
        send_notification()
    time.sleep(5)  # Kiểm tra mỗi 5 giây

# Bắt đầu theo dõi
monitor_chrome()
