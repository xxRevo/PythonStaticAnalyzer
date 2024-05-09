import magic # For filetype detection
from pathlib import Path # For filetype detection
import PyPDF2 # For scanning PDF
import PyPDF2.errors # For scanning PDF
import pdfplumber # For scanning PDF
import re # For finding specific strings in files
from docx import Document # For DOCX processing
from langdetect import detect # Detecting language in DOCX
from oletools.olevba import VBA_Parser # Detecting Macros in DOCX
import zipfile # Compressed file detection
import rarfile # Compressed file detection
import py7zr # Compressed file detection
import subprocess

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

# ------------------------------------COMPRESSED------------------------------------

def check_zip_password(file_path): # ZIP password
    try:
        with zipfile.ZipFile(file_path) as zf:
            if zf.testzip() is None:
                return "ZIP file is not password protected or is valid."
            else:
                return "ZIP file might be corrupted."
    except RuntimeError as e:
        if 'encrypted' in str(e):
            return "ZIP file is password protected."
        return "ZIP file raised a runtime error."
    
def check_rar_password(file_path): # RAR password
    try:
        with rarfile.RarFile(file_path) as rf:
            rf.extractall(pwd=None)
            return "RAR file is not password protected."
    except rarfile.NeedPassword:
        return "RAR file is password protected."

def check_7z_password(file_path):  # 7Z password
    try:
        with py7zr.SevenZipFile(file_path, mode='r') as z:
            z.extractall()
            return "7z file is not password protected."
    except py7zr.exceptions.PasswordRequired:
        return "7z file is password protected."

# ---------------------------------------DOCX---------------------------------------

def is_encrypted_docx(filepath): # Check for encyrption
    try:
        Document(filepath)
        print("File is not encyrpted.")
        return False
    except Exception:
        print("File is encyrpted.")
        return True
    
def is_password_protected_docx(filepath): # Check for password
    try:
        doc = Document(filepath)
        doc.paragraphs
        print("File is not password protected.")
        return False
    except Exception:
        print("File is password protected.")
        return True

def detect_language(filepath): # Detect language
    doc = Document(filepath)
    context = []
    for i in doc.paragraphs:
        context.append(i.text)
    text = ' '.join(context)
    print("File is written in:",detect(text))

def has_macros(file_path):
    vbaparser = VBA_Parser(file_path)
    if(vbaparser.detect_vba_macros()):
        print("This DOCX file has macros in it.")
    else:
        print("No macros found in the file.")

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
        print("This file appears to have the extension:", file_extension_name)
        print("This file has the extension:", file_extension_magic)
        print("\n")
    except Exception as err:
        print(err)
    return file_extension_magic

# ----------------------------------------PE----------------------------------------

def extract_strings(filepath):
    try:
        # Run the strings command
        result = subprocess.run(['strings', filepath], capture_output=True, text=True)
        # Return the output if the command was successful
        if result.returncode == 0:
            print(result.stdout)
        else:
            return result.stderr
    except FileNotFoundError:
        return "strings command not found."


# ---------------------------------------MAIN---------------------------------------

filename = input("Enter Filename: ")
filetype = get_filetype(filename)
compressed_list = ["application/zip","application/x-rar","application/x-7z-compressed"]
if (filetype == "pdf"):
    if( not is_password_protected_pdf(filename)):
        get_pdf_contents(filename)
elif (filetype == "vnd.openxmlformats-officedocument.wordprocessingml.document"):
    if(not is_encrypted_docx(filename)):
        if(not is_password_protected_docx(filename)):
            detect_language(filename)
            has_macros(filename)
elif(filetype == "application/zip"):
    check_zip_password(filename)
elif(filetype == "application/x-rar"):
    check_rar_password(filename)
elif(filetype == "application/x-7z-compressed"):
    check_7z_password(filename)
elif(filetype == "executable" or filetype == "dll"):
    extract_strings(filename)