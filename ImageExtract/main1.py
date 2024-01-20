import fitz  # PyMuPDF
from PIL import Image
from docx import Document
import io, os


def recoverpix(doc, item):
    xref = item[0]  # xref of PDF image
    smask = item[1]  # xref of its /SMask

    # special case: /SMask or /Mask exists
    if smask > 0:
        pix0 = fitz.Pixmap(doc.extract_image(xref)["image"])
        if pix0.alpha:  # catch irregular situation
            pix0 = fitz.Pixmap(pix0, 0)  # remove alpha channel
        mask = fitz.Pixmap(doc.extract_image(smask)["image"])

        try:
            pix = fitz.Pixmap(pix0, mask)
        except:  # fallback to original base image in case of problems
            pix = fitz.Pixmap(doc.extract_image(xref)["image"])

        if pix0.n > 3:
            ext = "pam"
        else:
            ext = "png"

        return {  # create dictionary expected by caller
            "ext": ext,
            "colorspace": pix.colorspace.n,
            "image": pix.tobytes(ext),
        }

    # special case: /ColorSpace definition exists
    # to be sure, we convert these cases to RGB PNG images
    if "/ColorSpace" in doc.xref_object(xref, compressed=True):
        pix = fitz.Pixmap(doc, xref)
        pix = fitz.Pixmap(fitz.csRGB, pix)
        return {  # create dictionary expected by caller
            "ext": "png",
            "colorspace": 3,
            "image": pix.tobytes("png"),
        }
    return doc.extract_image(xref)

def extract_images_from_pdf(pdf_path, output_folder):
    # Mở tệp PDF
    pdf_document = fitz.open(pdf_path)
    image_list = []
    xreflist = []
    dimlimit = 0  # 100  # each image side must be greater than this
    relsize = 0  # 0.05  # image : image size ratio must be larger than this (5%)
    abssize = 0  # 2048  # absolute image size limit 2 KB: ignore if smaller
    imgdir = "output" # found images are stored in this subfolder
    # Duyệt qua tất cả các trang
    for page_index in range(pdf_document.page_count):
        # Lấy trang
        page = pdf_document[page_index]

        il = pdf_document.get_page_images(page)
        image_list.extend([x[0] for x in il])

        for img in il:
            xref = img[0]
            if xref in xreflist:
                continue
            width = img[2]
            height = img[3]
            if min(width, height) <= dimlimit:
                continue
            image = recoverpix(pdf_document, img)
            n = image["colorspace"]
            imgdata = image["image"]

            if len(imgdata) <= abssize:
                continue
            if len(imgdata) / (width * height * n) <= relsize:
                continue

            imgfile = os.path.join(output_folder, "img%05i.%s" % (xref, image["ext"]))
            fout = open(imgfile, "wb")
            fout.write(imgdata)
            fout.close()
            xreflist.append(xref)

    # Đóng tệp PDF
    pdf_document.close()



def extract_images_from_word(docx_path, output_folder):
    # Mở tệp Word
    doc = Document(docx_path)

    # Duyệt qua tất cả các hình ảnh trong tệp Word
    for rel in doc.part.rels.values():
        if "image" in rel.reltype:
            image_blob = rel.target_part.blob
            image = Image.open(io.BytesIO(image_blob))
            
            # Lưu hình ảnh xuống thư mục đầu ra
            image.save(os.path.join(output_folder, f"image_{len(os.listdir(output_folder)) + 1}.png"))

# Thực hiện trích xuất hình ảnh từ tệp Word
extract_images_from_pdf('test.pdf', 'D:\learn_myself\/2years\Python_Project\ImageExtract')

