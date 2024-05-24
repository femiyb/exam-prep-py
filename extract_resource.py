import fitz  # Import PyMuPDF

def extract_text_from_pdf(pdf_path):
    """
    Extracts and returns the text from a PDF file.
    
    :param pdf_path: The path to the PDF file to be processed.
    :return: A string containing all the text extracted from the PDF.
    """
    text = ""
    with fitz.open(pdf_path) as doc:
        for page in doc:  # Iterate through each page
            text += page.get_text()
    return text

# Specify the path to your PDF file
pdf_path = 'resources/Cryptography-and-network-security-principles-and-practice.pdf'  # Update this to the path of your PDF

# Extract the text
extracted_text = extract_text_from_pdf(pdf_path)

# Optionally, save the extracted text to a file
with open('extracted_text.txt', 'w', encoding='utf-8') as f:
    f.write(extracted_text)

print("Text extraction completed.")
