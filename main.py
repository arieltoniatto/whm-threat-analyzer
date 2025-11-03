#!/usr/bin/env python3
"""
Pipeline Orchestrator for IP Processing Workflow
Executes 4 scripts in sequence with validation and detailed logging.
"""

import sys
import os
import subprocess
import json
import logging
from datetime import datetime
from pathlib import Path


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pipeline.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class PipelineOrchestrator:
    """Orchestrates the execution of the IP processing pipeline."""
    
    def __init__(self, initial_file):
        self.initial_file = initial_file
        self.start_time = None
        self.current_file = initial_file
        
        # Extract base filename info
        self.filename_parts = self._extract_filename_parts(initial_file)
        
        # Get current date for generated files (scripts use current date, not HTML date)
        self.current_date = datetime.now().strftime("%y-%m-%d")
        
        # Define script paths
        self.scripts = [
            'src/1_collect_whm_data.py',
            'src/2_process_ips.py',
            'src/3_enrich_ips.py',
            'src/4_generate_reports.py'
        ]
        
        # Expected output paths after each script (using current date, not HTML date)
        self.expected_outputs = [
            f"data/01_processed/whm_extracted/{self.current_date}_whm_{self.filename_parts['domain']}.json",
            f"data/02_intermediate/ip_lists/{self.current_date}_new-ips_{self.filename_parts['domain']}.json",
            f"data/03_enriched/ip_reputation/{self.current_date}_ip-reputation_{self.filename_parts['domain']}.json",
            f"reports/{self.current_date}_report_{self.filename_parts['domain']}.csv"
        ]
    
    def _extract_filename_parts(self, filepath):
        """Extract date and domain-account from filename."""
        filename = os.path.basename(filepath)
        # Remove extension (.html or .json)
        name_without_ext = filename.rsplit('.', 1)[0]
        
        # For HTML files: YY-MM-DD_dominio-conta
        # Extract date (first part before underscore)
        parts = name_without_ext.split('_', 1)
        
        return {
            'date': parts[0],  # YY-MM-DD
            'domain': parts[1] if len(parts) > 1 else name_without_ext  # domain-account
        }
    
    def validate_file_exists(self, filepath):
        """Validate that a file exists and is not empty."""
        if not os.path.exists(filepath):
            logger.error(f"File not found: {filepath}")
            return False
        
        if os.path.getsize(filepath) == 0:
            logger.error(f"File is empty: {filepath}")
            return False
        
        # For JSON files, try to validate structure
        if filepath.endswith('.json'):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if not data:
                        logger.warning(f"JSON file is empty: {filepath}")
                logger.info(f"✓ Valid JSON file: {filepath}")
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in {filepath}: {e}")
                return False
        elif filepath.endswith('.html'):
            logger.info(f"✓ HTML file exists and is not empty: {filepath}")
        
        return True
    
    def run_script(self, script_num, script_path, input_file):
        """
        Execute a script and return the output file path.
        
        Args:
            script_num: Script number (1-4)
            script_path: Path to the script
            input_file: Input file for the script
            
        Returns:
            str: Path to the output file if successful, None otherwise
        """
        logger.info("=" * 80)
        logger.info(f"EXECUTING SCRIPT {script_num}: {script_path}")
        logger.info(f"Input file: {input_file}")
        logger.info("=" * 80)
        
        script_start = datetime.now()
        
        try:
            # Validate input file
            if not self.validate_file_exists(input_file):
                raise FileNotFoundError(f"Input file validation failed: {input_file}")
            
            # Execute script
            result = subprocess.run(
                [sys.executable, script_path, input_file],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Log script output
            if result.stdout:
                logger.info(f"Script output:\n{result.stdout}")
            
            # Calculate execution time
            duration = (datetime.now() - script_start).total_seconds()
            logger.info(f"✓ Script {script_num} completed in {duration:.2f} seconds")
            
            # Validate output file
            expected_output = self.expected_outputs[script_num - 1]
            
            if not self.validate_file_exists(expected_output):
                raise FileNotFoundError(f"Expected output file not created: {expected_output}")
            
            logger.info(f"✓ Output file validated: {expected_output}")
            
            return expected_output
            
        except subprocess.CalledProcessError as e:
            logger.error(f"✗ Script {script_num} failed with exit code {e.returncode}")
            logger.error(f"Error output:\n{e.stderr}")
            return None
        
        except Exception as e:
            logger.error(f"✗ Error executing script {script_num}: {str(e)}")
            return None
    
    def run_pipeline(self):
        """Execute the complete pipeline."""
        self.start_time = datetime.now()
        
        logger.info("╔" + "═" * 78 + "╗")
        logger.info("║" + " " * 25 + "PIPELINE STARTED" + " " * 37 + "║")
        logger.info("╚" + "═" * 78 + "╝")
        logger.info(f"Initial file: {self.initial_file}")
        logger.info(f"Start time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Validate initial file
        if not self.validate_file_exists(self.initial_file):
            logger.error("Initial file validation failed. Aborting pipeline.")
            return False
        
        # Execute scripts in sequence
        for i, script_path in enumerate(self.scripts, start=1):
            output_file = self.run_script(i, script_path, self.current_file)
            
            if output_file is None:
                logger.error(f"Pipeline aborted at script {i}")
                self._print_summary(success=False, failed_at=i)
                return False
            
            # Update current file for next script
            self.current_file = output_file
            
            # Small delay between scripts
            if i < len(self.scripts):
                logger.info(f"→ Passing output to script {i+1}...")
        
        # Pipeline completed successfully
        self._print_summary(success=True)
        return True
    
    def _print_summary(self, success, failed_at=None):
        """Print pipeline execution summary."""
        duration = (datetime.now() - self.start_time).total_seconds()
        
        logger.info("\n" + "╔" + "═" * 78 + "╗")
        logger.info("║" + " " * 25 + "PIPELINE SUMMARY" + " " * 37 + "║")
        logger.info("╚" + "═" * 78 + "╝")
        
        if success:
            logger.info(f"✓ Status: COMPLETED SUCCESSFULLY")
            logger.info(f"✓ All {len(self.scripts)} scripts executed")
            logger.info(f"✓ Final outputs:")
            logger.info(f"  - Report: {self.expected_outputs[3]}")
            logger.info(f"  - Bulk reports updated: reports/bulk_reports.csv")
        else:
            logger.error(f"✗ Status: FAILED")
            logger.error(f"✗ Failed at script {failed_at}/{len(self.scripts)}")
        
        logger.info(f"⏱ Total execution time: {duration:.2f} seconds ({duration/60:.2f} minutes)")
        logger.info(f"⏱ End time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info("=" * 80)


def main():
    """Main entry point for the pipeline orchestrator."""
    
    if len(sys.argv) < 2:
        print("Usage: python main.py <path/to/YY-MM-DD_dominio-conta.html>")
        print("\nExample:")
        print("  python main.py data/00_raw/whm_logs/25-10-30_example-account.html")
        sys.exit(1)
    
    initial_file = sys.argv[1]
    
    # Validate initial file path format
    if not initial_file.startswith('data/00_raw/whm_logs/'):
        logger.warning(f"Input file is not in expected location (data/00_raw/whm_logs/)")
        logger.warning(f"Provided: {initial_file}")
    
    if not initial_file.endswith('.html'):
        logger.error(f"Input file must be an HTML file (.html extension)")
        logger.error(f"Provided: {initial_file}")
        sys.exit(1)
    
    # Create orchestrator and run pipeline
    orchestrator = PipelineOrchestrator(initial_file)
    success = orchestrator.run_pipeline()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()