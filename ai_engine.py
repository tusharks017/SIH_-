import os
import re
import io
import PyPDF2
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch

# PII Regex Patterns
PII_PATTERNS = {
    'SSN': r'\b\d{3}-\d{2}-\d{4}\b',
    'Credit Card': r'\b(?:\d[ -]*?){13,16}\b',
    'Email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'Phone': r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
    'IP Address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
}

def extract_text_from_file(file_path):
    """Extracts raw text from PDF or text-based files."""
    if not os.path.exists(file_path):
        return ""
    
    ext = os.path.splitext(file_path)[1].lower()
    text = ""
    
    try:
        if ext == '.pdf':
            reader = PyPDF2.PdfReader(file_path)
            pages_text = []
            for i, page in enumerate(reader.pages):
                extracted = page.extract_text()
                if extracted:
                    pages_text.append(extracted)
            text = "\n".join(pages_text)
        elif ext in ['.txt', '.log', '.csv', '.json', '.md', '.html', '.xml']:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
    except Exception as e:
        print(f"Error extracting text from {file_path}: {e}")
        
    return text.strip()

def generate_ai_summary(text, original_filename="Document"):
    """Generates an executive legal summary of the document text."""
    if not text or len(text.strip()) < 30:
        return f"Executive Summary: Small or binary document file ({original_filename}). Text extraction yielded minimal content."
    
    clean_text = ' '.join(text.split())
    sentences = re.split(r'(?<=[.!?]) +', clean_text)
    
    # Identify key legal/investigative terms
    key_terms = ['agreement', 'contract', 'court', 'plaintiff', 'defendant', 'evidence', 'section', 'liability', 'investigation', 'shall', 'pursuant', 'confidential', 'party']
    scored_sentences = []
    
    for sentence in sentences:
        if len(sentence.strip()) < 15:
            continue
        score = sum(1 for word in sentence.lower().split() if word in key_terms)
        scored_sentences.append((score, sentence.strip()))
        
    scored_sentences.sort(key=lambda x: x[0], reverse=True)
    top_sentences = [s[1] for s in scored_sentences[:3]]
    
    if not top_sentences:
        top_sentences = sentences[:3]
        
    summary_bullets = "\n".join([f"• {s}" for s in top_sentences if s])
    
    result = f"📌 EXECUTIVE SUMMARY ({original_filename}):\n{summary_bullets}\n\n🔒 CONFIDENTIALITY NOTICE: Processed by SECURELEX AI Intelligence Engine."
    return result

def classify_and_tag(text, filename=""):
    """Classifies document and suggests category & case tags based on keywords."""
    combined_content = (filename + " " + text).lower()
    
    category = "General Brief"
    if any(k in combined_content for k in ['contract', 'agreement', 'terms', 'lease', 'nda', 'memorandum']):
        category = "Contract & Agreement"
        case_prefix = "CTR"
    elif any(k in combined_content for k in ['court', 'subpoena', 'warrant', 'summons', 'order', 'judge', 'ruling']):
        category = "Court Order & Subpoena"
        case_prefix = "CRT"
    elif any(k in combined_content for k in ['affidavit', 'statement', 'deposition', 'testimony', 'witness']):
        category = "Affidavit & Witness Statement"
        case_prefix = "AFF"
    elif any(k in combined_content for k in ['evidence', 'forensic', 'investigation', 'exhibit', 'report', 'audit']):
        category = "Evidence & Investigation"
        case_prefix = "INV"
    elif any(k in combined_content for k in ['invoice', 'financial', 'tax', 'receipt', 'payment', 'audit', 'bank']):
        category = "Financial Record"
        case_prefix = "FIN"
    else:
        case_prefix = "SEC"
        
    # Extract case pattern if already present in text (e.g. SEC-2026-9912 or CASE-1234)
    case_match = re.search(r'\b[A-Z]{2,4}-\d{4}-\d{3,5}\b', text)
    if case_match:
        case_tag = case_match.group(0)
    else:
        # Generate clean standard tag
        import hash_id
        import random
        num = random.randint(1000, 9999)
        case_tag = f"{case_prefix}-2026-{num}"
        
    return category, case_tag

def detect_pii(text):
    """Detects PII matches in text."""
    found = {}
    for pii_type, pattern in PII_PATTERNS.items():
        matches = list(set(re.findall(pattern, text)))
        if matches:
            found[pii_type] = matches
    return found

def redact_document_text(original_text, terms_to_redact, auto_pii=True):
    """Redacts specified terms and auto PII from text content."""
    redacted = original_text
    
    if auto_pii:
        for pii_type, pattern in PII_PATTERNS.items():
            redacted = re.sub(pattern, f"[REDACTED-{pii_type.upper()}]", redacted)
            
    for term in terms_to_redact:
        if term.strip():
            escaped = re.escape(term.strip())
            redacted = re.sub(escaped, "[REDACTED]", redacted, flags=re.IGNORECASE)
            
    return redacted
