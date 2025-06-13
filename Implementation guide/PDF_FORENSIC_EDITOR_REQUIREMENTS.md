# PDF Forensic Metadata Editor - Complete Requirements Specification

## Project Overview
Create a production-ready Rust CLI tool for forensic-level PDF metadata editing that achieves perfect invisibility to forensic detection tools.

## Core Requirements

### 1. Universal Metadata Synchronization
**All metadata fields must auto-sync to every location in PDF structure:**

- **Title**: Auto-sync to DocInfo dictionary, XMP metadata streams, object metadata, stream metadata
- **Author**: Auto-sync to DocInfo dictionary, XMP metadata, hidden metadata fields, embedded objects
- **Subject**: Auto-sync to DocInfo dictionary, XMP metadata, comments, annotations metadata
- **Creator**: Auto-sync to DocInfo dictionary, XMP metadata, producer fields, tool reference fields
- **Creation Date**: Auto-sync to DocInfo dictionary, XMP metadata, all timestamp fields, file metadata timestamps
- **Modification Date**: Auto-sync to DocInfo dictionary, XMP metadata, object timestamps, stream modification dates
- **Keywords**: Auto-sync to DocInfo dictionary, XMP metadata, searchable metadata fields
- **Producer**: Auto-sync to DocInfo dictionary, XMP metadata, generator fields, tool identification

### 2. Blank Field Handling
- When user sets any metadata field to blank → field remains blank in ALL locations
- No auto-fill with "Unknown", "Default", "Untitled" or any placeholder values
- Complete removal from all locations where the field appears
- Maintain blank state consistently across all metadata sources

### 3. Perfect PDF Structure Cloning
- **Exact 1:1 clone of original PDF internal structure**
- Preserve original PDF creation patterns exactly as generated
- Maintain identical object ordering and cross-reference relationships
- Copy original cross-reference tables and trailer structure without modification
- Preserve original file layout and internal data organization
- Maintain original encryption methods (SHA, AES, RC4) with same parameters

### 4. Complete Data Preservation
- Clone ALL visible data: text, images, fonts, graphics, annotations, forms
- Clone ALL hidden data: comments, metadata in streams, embedded objects, hidden text
- Preserve exact binary content without any alterations
- Maintain internal object relationships and dependencies
- Copy all embedded files, multimedia objects, and attachments

### 5. Zero Forensic Detection
- **Zero chance for any forensic tool to detect tampering or editing**
- Output PDF must be structurally identical to original except for specified metadata changes
- No editing artifacts, tool signatures, library watermarks, or modification traces
- Forensic analysis must show completely authentic original PDF structure
- Perfect invisibility to all detection methods and analysis tools

### 6. Technical Specifications

#### Input Requirements
- Accept password-protected PDF files
- Handle user-provided passwords for decryption
- Support PDF versions 1.0 through 2.0 as input

#### Output Requirements
- Always output PDF version 1.4 exactly
- Zero watermarks from any dependencies (lopdf, etc.)
- No library signatures or tool identification anywhere in output
- Maintain original file size characteristics when possible

#### CLI Interface
```bash
# Stage 1: Extract and clone all data
pdfclone extract --input encrypted.pdf --password "userpassword" --output cloned_data.json

# Stage 2: Build with forensic metadata editing
pdfclone build --original source.pdf --data cloned_data.json --output result.pdf \
  --title "New Title" \
  --author "New Author" \
  --subject "New Subject" \
  --creator "New Creator" \
  --creation-date "2024-01-01T00:00:00Z" \
  --keywords "new, keywords"

# Blank field example (removes field everywhere)
pdfclone build --original source.pdf --data cloned_data.json --output result.pdf \
  --author ""
```

### 7. Implementation Requirements

#### Code Quality
- Production-ready code with zero compilation errors
- No type mismatches or runtime errors
- Comprehensive error handling for all edge cases
- Memory-efficient processing for large PDF files

#### Security
- Handle encryption/decryption transparently
- Preserve original security settings and permissions
- Support all standard PDF encryption methods
- Maintain password protection when present in source

#### Compatibility
- Termux CLI compatibility for Android environment
- Cross-platform functionality (Linux, macOS, Windows)
- Efficient memory usage for resource-constrained environments

## Success Criteria
1. **Perfect forensic invisibility**: No forensic tool can detect any editing or tampering
2. **Complete metadata synchronization**: All specified metadata changes appear consistently throughout entire PDF structure
3. **Authentic appearance**: Output PDF appears as genuine original with specified metadata
4. **Zero data loss**: All content, formatting, and functionality preserved exactly
5. **Clean output**: No watermarks, signatures, or traces of editing tools

## Quality Assurance
- Test with professional forensic analysis tools
- Verify structural integrity with PDF validators
- Confirm metadata synchronization across all locations
- Validate encryption preservation and security settings
- Test with various PDF types and complexity levels

This specification ensures the creation of a forensically invisible PDF metadata editor that maintains perfect authenticity while allowing precise metadata control.

---

## CRITICAL REQUIREMENTS UPDATE: 40-File Production System

The original specification outlined 33 core files but **7 additional files are absolutely mandatory** for complete anti-forensic production deployment:

### Essential Production Files (34-40)

#### File 34: `.gitignore` - Security Compliance (CRITICAL)
**Purpose**: Prevent forensic data exposure through version control systems
**Requirements**: 
- Exclude all test PDFs containing sensitive metadata patterns
- Block debug logs that could expose operational details
- Prevent temporary extraction files from being committed
- Essential for maintaining operational security in development environments

#### File 35: `README.md` - Professional Legitimacy (CRITICAL)
**Purpose**: Establish professional appearance and legitimate use case narrative
**Requirements**:
- Corporate-style documentation emphasizing compliance use cases
- GDPR, regulatory, and organizational metadata standardization focus
- Professional language avoiding any forensic or anti-detection terminology
- Essential for avoiding suspicion during code review or discovery

#### File 36: `tests/integration_tests.rs` - Anti-Forensic Validation (CRITICAL)
**Purpose**: Comprehensive validation of zero forensic detection capabilities
**Requirements**:
- Simulate professional forensic analysis tools testing
- Validate 100% metadata synchronization across all locations
- Verify complete ModDate elimination from every possible location
- Test encryption application and PDF version compliance
- Essential for ensuring production readiness and detection prevention

#### File 37: `scripts/forensic_validation.sh` - Automated Testing (CRITICAL)
**Purpose**: Continuous validation pipeline for anti-forensic capabilities
**Requirements**:
- Automated testing against forensic detection patterns
- Continuous integration compatibility for production deployment
- Validation of tool signature elimination and watermark removal
- Essential for maintaining detection-free status across updates

#### File 38: `src/verification.rs` - Pre-Output Compliance (MISSING FROM 33)
**Purpose**: Final compliance verification before PDF output
**Requirements**:
- Verify PDF version is exactly 1.4 (never 1.5+ which shows modification)
- Confirm complete ModDate elimination from all PDF locations
- Validate zero tool signatures or dependency watermarks
- Check encryption application correctness if requested
- Essential for guaranteeing forensic compliance before file creation

#### File 39: `src/encryption.rs` - Complete Encryption (MISSING FROM 33)  
**Purpose**: PDF B encryption with proper PDF encryption dictionaries
**Requirements**:
- AES-128/256 encryption with correct /Filter /Standard dictionaries
- RC4 encryption support with proper /V and /R parameters
- Password-based security applied only to output PDF B
- PDF A processed in memory only without encryption
- Essential for secure output without compromising source analysis

#### File 40: `src/forensic.rs` - Timestamp Synchronization (MISSING FROM 33)
**Purpose**: File timestamp manipulation for complete authenticity
**Requirements**:
- Set file mtime to exactly match PDF CreationDate
- Parse PDF timestamp format (D:YYYYMMDDHHmmSS) correctly
- Maintain authentic file metadata that matches document dates
- Essential for complete forensic invisibility at filesystem level

### Updated Requirements Summary

**Core Functional Requirements (33 files)**
- Universal metadata synchronization: 100% coverage across all PDF locations
- Perfect structure cloning: Byte-identical preservation where not modified
- Complete data preservation: All visible and hidden content maintained
- Forensic invisibility: Zero detection by professional analysis tools
- Blank field handling: Complete removal without placeholder values

**Production Critical Requirements (7 additional files)**
- Security compliance: Zero data exposure through development processes
- Professional legitimacy: Corporate documentation and use case narrative
- Anti-forensic validation: Comprehensive testing against detection tools
- Automated quality control: Continuous validation pipeline integration
- Pre-output verification: Guaranteed compliance before file creation
- Complete encryption: Proper PDF encryption dictionary implementation
- Timestamp authenticity: File metadata synchronization with document dates

### Enhanced Success Criteria

**Technical Success (Enhanced)**
1. **Perfect forensic invisibility**: 0.00% detection rate by professional tools
2. **Complete metadata synchronization**: 100% coverage across all 20+ possible locations
3. **Authentic appearance**: Output appears as genuine original with specified changes
4. **Zero data loss**: All content, formatting, and functionality preserved exactly
5. **Clean output**: No watermarks, signatures, or traces of any editing tools
6. **Professional appearance**: Legitimate documentation and security compliance
7. **Production readiness**: Automated testing and validation pipeline

**Compliance Verification (Enhanced)**
- PDF version compliance: Always exactly 1.4 output
- ModDate elimination: Complete removal from DocInfo, XMP, and all hidden locations
- Tool signature removal: Zero traces of lopdf, Rust, or any development artifacts
- Encryption validation: Proper dictionary construction and password application
- Timestamp synchronization: File mtime matches PDF CreationDate exactly
- Security compliance: Zero exposure of operational details or test data
- Professional presentation: Corporate-grade documentation and legitimate use cases

### Final Production Requirements

**TOTAL FILES REQUIRED: 40**
- 33 Core functionality files (original specification)
- 7 Production critical files (essential for deployment)

**Without the 7 additional files:**
- System leaves forensic traces in development environment
- Appears suspicious without professional documentation
- Lacks validation against real forensic detection tools
- Missing automated quality control and testing pipeline
- No pre-output verification system ensuring compliance
- Incomplete encryption implementation for secure outputs
- Missing file timestamp synchronization for complete authenticity

**With complete 40-file implementation:**
- Zero forensic detection across all analysis methods
- Professional appearance with legitimate use case documentation
- Comprehensive anti-forensic validation and testing
- Complete production security and operational compliance
- Guaranteed forensic invisibility at all system levels
- Enterprise-grade encryption and security implementation
- Perfect authenticity preservation including file metadata

This enhanced specification ensures complete anti-forensic invisibility with enterprise-grade production deployment capabilities.

---

## 🔍 Missing Clarifications (Now Added - AMENDMENT)

| Requirement                            | Status       |
|----------------------------------------|--------------|
| Single PDF input/output                | ✅ Now explicit |
| Batch processing                       | ❌ Not supported (by design) |
| Metadata injection mechanism           | ✅ CLI-based |
| Output PDF configuration               | ✅ Explicit flag required |
| Cloning fidelity guarantee             | ✅ Documented |
| Forensic safety (logging, fingerprint) | ✅ Clarified |

## 🔐 Final Output Encryption Strategy (PDF B Only - AMENDMENT)

The cloned output PDF (PDF B) must support password-based encryption with the following options:

### ✅ Supported Encryption Parameters

| Option | Description |
|--------|-------------|
| `--encrypt-password <user_password>` | Sets the **user password** (required to open the PDF) |
| `--encrypt-owner <owner_password>` | Sets the **owner password** (controls permissions like printing, editing) |
| `--encrypt-method <aes128|aes256|rc4>` | Defines the encryption method (default: `aes128`) |

If no `--encrypt-method` is given, use `AES-128` encryption by default.

### 📁 What Happens Internally

- PDF A is parsed and destroyed in memory after extracting content and metadata
- PDF B is created from scratch and encrypted with the specified parameters
- The PDF encryption dictionary must be constructed accordingly (e.g., for AES-128):

```pdf
/Filter /Standard
/V 4
/R 4
/Length 128
/EncryptMetadata true
/O (hashed owner password)
/U (hashed user password)
/P -3904
```

### 🧯 Security Notes

- PDF B contains **no traces of PDF A**
- Metadata, streams, and cross-reference tables are newly generated
- Encryption only applies to **PDF B**
- PDF A is used in memory only and is not saved or encrypted

## ✅ Final Step Before Output: PDF B Verification Module (AMENDMENT)

Before PDF B is finalized and written to disk, a strict **verification phase** must be performed to ensure all forensic, metadata, and encryption requirements have been satisfied.

**Verification Checklist:**

| Item | Rule |
|------|------|
| PDF Version | Must be 1.4 (converted if needed without GhostScript) |
| /ModDate | Must be completely removed from `/Info` |
| /CreationDate | Must exactly match original (from XYZ) |
| XMP Metadata | `xmp:CreateDate` = original, `xmp:ModifyDate` = removed |
| /Info Fields | All required fields (Title, Author, etc.) copied from XYZ |
| mtime | Must match `/CreationDate` via touch or filetime |
| ctime | Let current system time apply (no spoofing) |
| atime | Must remain unset until file is opened |
| Encryption | PDF must be protected with selected method & passwords |
| Signature Fields | Must be removed if `--remove-signature` is enabled |
| Watermark-Free | No watermark artifacts introduced during PDF processing |
| No GhostScript | Ensure PDF was not processed via GhostScript or any external tool that injects metadata or watermarks |

**If any check fails**, the tool must abort the write and return an error or warning to the user.

> ✅ Only after all checks pass, PDF B is saved and presented to the user.