from pynotifier import Notification, NotificationClient

c = NotificationClient()
a = Notification(
    title='Title',
    description='Hello, Windows Notification!',
    duration=5,  # Thời gian hiển thị thông báo (giây)
)
c.notify_all(a)

# from win10toast import ToastNotifier
# import time

# t = ToastNotifier()

# t.show_toast("help !", "hello there")
# while t.notification_active(): time.sleep(0.1)