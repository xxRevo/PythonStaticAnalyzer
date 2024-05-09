import magic # For filetype detection
from pathlib import Path # For filetype detection
import PyPDF2 # For scanning PDF
import PyPDF2.errors # For scanning PDF
import pdfplumber # For scanning PDF
import re # For finding specific strings in files
from docx import Document # For DOCX processing

# ---------------------------------------.PDF--------------------------------------- 

def is_password_protected_pdf(filepath): # Check if PDF is encyrpted.
    try:
        with open(filepath, "rb") as file:
            pdf_reader = PyPDF2.PdfReader(file)
            if pdf_reader.is_encrypted:
                print("This PDF file is password protected.\n")
                return True
            else:
                print("This PDF file is not password protected.\n")
                return False
    except Exception as err:
        print("Error while processing the PDF file.\n")
        print(err)
        return True

def get_pdf_contents(filepath): # Read contents of the PDF file.
    urls = []
    ips = []
    domains = []
    url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    domain_pattern = re.compile(r'\b(?:[\w-]+\.)+[a-zA-Z]{2,6}(?!\.\w+)\b')
    with pdfplumber.open(filepath) as pdf:
        pages = pdf.pages
        for page in pages:
            text = page.extract_text()
            if text:
                urls.extend(url_pattern.findall(text))
                ips.extend(ip_pattern.findall(text))
                domains.extend(domain_pattern.findall(text)) #fix domain issue
    print("URLs:")
    for i in urls:
        print(i)
    print("----------\nIPs:")
    for i in ips:
        print(i)
    print("----------\nDomains:")
    for i in domains:
        print(i)
    print("\n")

# ---------------------------------------.ZIP---------------------------------------

# ---------------------------------------DOCX---------------------------------------

def is_encrypted_docx(filepath):
    try:
        Document(filepath)
        print("File is not encyrpted.\n")
        return False
    except Exception:
        print("File is encyrpted.\n")
        return True
    
def is_password_protected_docx(filepath):
    try:
        doc = Document(filepath)
        doc.paragraphs
        print("File is not password protected.")
        return False
    except Exception:
        print("File is password protected.")
        return True

# -------------------------------------FILETYPE-------------------------------------

def get_extension_name(filepath): # Get filetype based on filename
    return Path(filepath).suffix[1:]

def get_extension_magic(filepath): # Get filetype based on magic value
    magic_obj = magic.Magic(mime=True)
    file_type = magic_obj.from_file(filepath)
    file_type = file_type.split('/')[1]
    return file_type

def get_filetype(filename): # Main function to handle filetype operations
    try:
        file_extension_name = get_extension_name(filename)
        file_extension_magic = get_extension_magic(filename)
        if (file_extension_name not in file_extension_magic):
            print("Mismatch between actual extension and the filename extension in the file!!!")
            print("This file might be a malware!!!")
            print("This file appears to have the extension:", file_extension_name)
            print("This file has the extension:\n", file_extension_magic)
        else:
            print("This file has the extension:\n", file_extension_magic)
    except Exception as err:
        print(err)
    return file_extension_magic

# ---------------------------------------MAIN---------------------------------------

filename = input("Enter Filename: ")
filetype = get_filetype(filename)
if (filetype == "pdf"):
    if( not is_password_protected_pdf(filename)):
        get_pdf_contents(filename)
if (filetype == ".docx" or filetype == ".doc"):
    if(not is_encrypted_docx(filename)):
        if(not is_password_protected_docx(filename)):
            print("bruh")