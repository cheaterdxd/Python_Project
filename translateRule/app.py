from flask import Flask, render_template, request
from select_and_show.select_and_show import show_rule_bp
app = Flask(__name__)
app.register_blueprint(show_rule_bp,template_folder="select_and_show/templates", static_folder = "select_and_show/static")

if __name__ == '__main__':
    app.run(debug=True)
