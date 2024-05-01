import sys
import magic

def identify_file_format(file_path):
    magic_obj = magic.Magic(mime=True)
    with open(file_path, 'rb') as file:
        file_type = magic_obj.from_buffer(file.read(2048))
    return file_type

file_path = sys.argv[1] if len(sys.argv) > 1 else input("Enter the file path: ")
detected_format = identify_file_format(file_path)
print(f"The detected file format is: {detected_format}")