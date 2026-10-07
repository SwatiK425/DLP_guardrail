#!/usr/bin/env python
"""
Run Ingestion Pipeline - CLI Entry Point
"""
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from experiments.ingestion_pipeline import run_ingestion

if __name__ == "__main__":
    print("Starting Eval Dataset Ingestion Pipeline")
    print("=" * 60)
    
    try:
        result = run_ingestion()
        print("\n" + "=" * 60)
        print("INGESTION COMPLETE")
        print("=" * 60)
        print(f"Golden Test: {result['golden_count']} cases")
        print(f"Dev Train:   {result['dev_count']} cases")
        print(f"Rejected:    {result['rejected_count']} cases")
        
        # Check if we met targets
        golden_ok = result['golden_count'] >= 1000
        dev_ok = result['dev_count'] >= 500
        
        if golden_ok and dev_ok:
            print("\n✅ ALL TARGETS MET")
            sys.exit(0)
        else:
            print(f"\n⚠️ TARGETS NOT MET (Golden: {result['golden_count']}/1000, Dev: {result['dev_count']}/500)")
            sys.exit(1)
            
    except Exception as e:
        print(f"\n❌ INGESTION FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)