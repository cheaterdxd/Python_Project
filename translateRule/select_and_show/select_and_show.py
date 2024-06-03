from flask import Blueprint, render_template, request, url_for
import os


show_rule_bp = Blueprint("select_and_show_rule", __name__, template_folder="templates",static_folder="static", static_url_path="/rule_type")

@show_rule_bp.route('/', methods=['GET', 'POST'])
def index():
    return render_template('select_and_display_file.html')

@show_rule_bp.route("/show_rule", methods = ['GET', 'POST'])
def show_platform_rule():
    platform = request.args.get('platform')
    print(platform)
    if platform == "edr":
        rule_path = "select_and_show\static\/rule_template\edr\\"
    else:
        rule_path = "select_and_show\static\/rule_template\siem\\"

    if request.method == 'POST':
        selected_file = request.form.get('file_select')

        if selected_file:
            # Đọc nội dung từ file được chọn
            file_path = os.path.join(rule_path, selected_file)
            with open(file_path, 'r') as file_content:
                content = file_content.read()

            return render_template('display_selected_file.html', file_content=content)

    # Lấy danh sách các file từ thư mục 'files'
    file_list = os.listdir(rule_path)

    return render_template('select_and_display_file.html', file_list=file_list)