use clap::Parser;
use std::process;
use pdf_forensic_editor::{
    cli::CliArgs,
    errors::{ForensicError, Result},
    pdf::{parser::PdfParser, cloner::PdfCloner, reconstructor::PdfReconstructor},
    metadata::{editor::MetadataEditor, synchronizer::MetadataSynchronizer},
    verification::OutputVerifier,
    forensic::TimestampManager,
};

fn main() {
    let args = CliArgs::parse();
    
    if let Err(e) = run_forensic_editor(args) {
        eprintln!("Error: {}", e);
        
        // Chain error causes for debugging
        let mut source = e.source();
        while let Some(err) = source {
            eprintln!("Caused by: {}", err);
            source = err.source();
        }
        
        process::exit(1);
    }
}

fn run_forensic_editor(args: CliArgs) -> Result<()> {
    // Phase 1: Parse input PDF (PDF A)
    let mut parser = PdfParser::new();
    let pdf_data = parser.parse_file(&args.input)?;
    
    // Phase 2: Extract complete PDF structure and metadata
    let extraction_data = parser.extract_complete_structure(&pdf_data)?;
    
    // Phase 3: Apply metadata modifications
    let mut metadata_editor = MetadataEditor::new();
    let modified_metadata = metadata_editor.apply_changes(&extraction_data, &args)?;
    
    // Phase 4: Synchronize metadata across all locations
    let mut synchronizer = MetadataSynchronizer::new();
    let synchronized_data = synchronizer.synchronize_all_metadata(&modified_metadata)?;
    
    // Phase 5: Clone and reconstruct PDF (PDF B)
    let mut cloner = PdfCloner::new();
    let cloned_structure = cloner.clone_with_modifications(&synchronized_data)?;
    
    // Phase 6: Reconstruct final PDF
    let mut reconstructor = PdfReconstructor::new();
    let final_pdf = reconstructor.rebuild_pdf(&cloned_structure)?;
    
    // Phase 7: Apply encryption if specified
    let encrypted_pdf = if args.has_encryption() {
        crate::encryption::apply_encryption(&final_pdf, &args)?
    } else {
        final_pdf
    };
    
    // Phase 8: Pre-output verification
    let verifier = OutputVerifier::new();
    verifier.verify_compliance(&encrypted_pdf)?;
    
    // Phase 9: Write output file
    std::fs::write(&args.output, &encrypted_pdf)?;
    
    // Phase 10: Synchronize file timestamps
    let timestamp_manager = TimestampManager::new();
    timestamp_manager.synchronize_timestamps(&args.output, &synchronized_data.creation_date)?;
    
    println!("PDF processing completed successfully");
    println!("Input: {}", args.input);
    println!("Output: {}", args.output);
    
    Ok(())
}
