import kivy
kivy.require('2.3.0') # replace with your current kivy version !

from kivy.lang import Builder
from kivy.app import App
# from kivy.uix.label import Label
# from kivy.uix import boxlayout, gridlayout

root = Builder.load_file("D:\PROGRAMMING_container\Python_Project\Personal_dashboard\Personal-Dashboard\mygui.kv")

class MyApp(App):

    def build(self):
        return root

if __name__ == '__main__':
    MyApp().run()