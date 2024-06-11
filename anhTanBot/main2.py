import pandas as pd

# Read the entire Excel file (first sheet by default)
# df = pd.read_excel('danhsachlop.xlsx')
# print(df)


    

def get_class_user_id_from_danh_sach(class_name: str) -> list:
    """Hàm sử dụng để lấy danh sách từ file danhsachlop.xlsx

    Args:
        class_name (str): tên lớp

    Returns:
        list: danh sách tên hiển thị của các học viên trong lớp
    """
    if class_name != "":
        # Read a specific sheet by index (e.g., sheet2)
        class_type_df: pd.DataFrame = pd.read_excel('danhsachlop.xlsx', sheet_name=1)
        column_list = list(class_type_df.items())
        for col in column_list:
            if(col[1].name == class_name):
                return list(col[1])
for i in get_class_user_id_from_danh_sach("T4"):
    print("a= " , i)
'''
# Read a specific sheet by name (e.g., 'sheet2')
df_sheet_name = pd.read_excel('sample.xlsx', sheet_name='sheet2')
print(df_sheet_name)

# Read multiple sheets (e.g., first sheet and 'sheet2')
df_sheet_multi = pd.read_excel('sample.xlsx', sheet_name=[0, 'sheet2'])
print(df_sheet_multi[0])  # First sheet
print(df_sheet_multi['sheet2'])  # 'sheet2'
'''