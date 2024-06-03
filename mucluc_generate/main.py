from sys import argv
import pathlib
import subprocess

is_debug = False

start_html = '''
<!DOCTYPE html>
<html>
'''
end_html = "</html>"


head = ""
body = ""

end_header = "\n</li>"


def header_gen(class_, id, content):
    ret = ""
    bold = False
    content = content.replace('\n',"")
    if(class_ == "h1"):
        bold = True
    if(bold):
        ret = f'''<li class="{class_}">
    <div>
        <p id="{id}" style="font-weight: bold;">{content}</p>
    </div>'''
    else:
        ret = f'''<li class="{class_}">
    <div>
        <p id="{id}">{content}</p>
    </div>''' 
    return ret

def help():
    print("Cách dùng: ./mucluc_generate.exe [file mục lục]")
    exit

def check_legit_id(id):
    a = str(id.replace("\n","").split(":")[1])
    if(a.isdigit() is False):
        print("Load ID format failed ! Exit now")
        print(id)
        exit
    return int(a)


def count_indent(line):
    return line.count(".")

def gen(file_mucluc):
    mucluchtml = ""
    with open(file_mucluc, 'r', encoding='utf-16le') as f_ml:
        content = f_ml.readlines()
        current_id = -1
        current_header_level = -1
        is_ul_use = [False,0]
        for line in content:
            if(is_debug):
                print(f"===========================================\n[+] xu ly : {line}")
            if (current_id==-1): # chưa xử lý 1 id nào
                if("id:" not in line): # nếu không check đc id của đoạn
                    print("Fail to load format.")
                    print(line)
                    exit
                else: # đã check được id của đoạn
                    if(is_debug):
                        print(line.split(":"))
                    current_id = check_legit_id(line) # set current id
                    continue
            elif current_id > 0: # đang xét id nào đó
                # nhận dòng id mới
                if("id:" in line):
                    # cập nhật id mới
                    current_id = check_legit_id(line)
                    continue
            if current_header_level>0: # Đang xử lý 1 header nào đó
                if(count_indent(line) == current_header_level): # nghĩa là cái header đang xử lý không có con, line mới bằng với line cũ
                    mucluchtml += end_header  # đóng line cũ
                    # thêm line mới
                    mucluchtml += header_gen('h'+str(current_header_level),current_id,line.strip())
                    if(is_debug):
                        print("new data: "+mucluchtml)
                elif count_indent(line)>current_header_level:
                    # nghĩa là nó gặp con của nó
                    mucluchtml += "\n<ul>"
                    # tăng tiến số lượng ul đang mở 
                    is_ul_use[0] = True
                    is_ul_use[1] += 1

                    current_header_level = count_indent(line) # cập nhật level
                    mucluchtml+= header_gen("h"+str(current_header_level),current_id,line.strip()) 
                    if(is_debug):
                        print("new data: "+mucluchtml)
                elif count_indent(line) < current_header_level:
                    #nghĩa là nó gặp header tiếp theo nó và lớn bằng/hơn cha nó --> nên đóng nó và cha nó luôn
                    if is_debug: 
                        print(is_ul_use)
                    # đóng li của con
                    mucluchtml += end_header
                    # đóng ul của cha nó, nhưng không phải lúc nào line này cũng lớn = cha nó mà chỉ đóng 1 lần, phải tính chênh lệch độ lớn rồi đóng cho đến khi về tới level của line này 
                    while(count_indent(line) < current_header_level):
                        mucluchtml += "\n</ul>"
                        mucluchtml += end_header
                        current_header_level -= 1 # giảm vì đã đóng
                    # if(is_ul_use[0]): # phải đóng ul
                    #     mucluchtml += "\n</ul>"
                    #     if(is_ul_use[1] >0): # vẫn còn ul ở parent
                    #         is_ul_use[1] -= 1 # giảm ul đã được mở
                    #     else: # đã ko còn ul nào được dùng nữa
                    #         is_ul_use[0] = False #
                    # cập nhật lại current level
                    current_header_level = count_indent(line)

                    # tạo header mới cho line mới
                    mucluchtml+= header_gen("h"+str(current_header_level),current_id,line.strip())
                    if(is_debug):
                        print("new data: "+mucluchtml)
            elif current_header_level==-1: # đã nhận id, chưa nhận header đầu tiên
                current_header_level = count_indent(line)
                if(current_header_level==1):
                    mucluchtml+=header_gen("h1",current_id, line.strip())
                    if(is_debug):
                        print("new data: "+mucluchtml)
    # print('\n'*5+"reponse:\n" + mucluchtml)
    # nếu hết mà chưa xử lý được hết indent
    mucluchtml += end_header # xử lý cái <li> gần nhất (dù ở level nào)
    # xử lý số lượng <ul> và <li> còn lại
    while(current_header_level>1):
        mucluchtml += "\n</ul>"
        mucluchtml += end_header
        current_header_level -= 1 # giảm vì đã đóng
    return mucluchtml


if(len(argv)<2):
    help()
else:
    file_path = str(argv[1])
    if pathlib.Path(file_path).exists() is True:
        print(f'[+] file {file_path} ton tai.')
        data = gen(file_path)
        print(data)
        with open("template_head.txt",'r') as head, open("template_body.txt", 'r') as body:
            head_content = head.read()
            body_content = body.read()
            body_content = body_content.replace('body_space_holder', data) 
            with open(file_path+".html", "w",encoding='utf-16le') as writehtml:
                writehtml.write(head_content+body_content)
                subprocess.run("code "+ file_path + ".html", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)