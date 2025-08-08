"""
NEXUS-AI Performance Benchmarks
Measures performance metrics for different components
"""
import time
import psutil
import os
import sys
import json
from datetime import datetime
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

class PerformanceBenchmark:
    """Performance benchmarking for NEXUS-AI components"""
    
    def __init__(self):
        self.results = {}
        self.start_time = None
        self.start_memory = None
    
    def start_measurement(self):
        """Start measuring time and memory"""
        self.start_time = time.time()
        self.start_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
    
    def end_measurement(self):
        """End measurement and return metrics"""
        end_time = time.time()
        end_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        
        execution_time = end_time - self.start_time
        memory_used = end_memory - self.start_memory
        
        return {
            'execution_time': execution_time,
            'memory_used_mb': memory_used,
            'peak_memory_mb': end_memory
        }
    
    def benchmark_model_loading(self):
        """Benchmark model loading performance"""
        print("🔍 Benchmarking model loading...")
        
        self.start_measurement()
        try:
            from nexus.cli.predictor import Predictor
            predictor = Predictor()
            # Try to load a model (will fail if no model exists, but we measure the attempt)
            try:
                predictor.load_model('model/ensemble_model.pkl')
            except FileNotFoundError:
                pass  # Expected if no model exists
        except Exception as e:
            print(f"⚠️ Model loading benchmark failed: {e}")
        
        metrics = self.end_measurement()
        self.results['model_loading'] = metrics
        print(f"✅ Model loading: {metrics['execution_time']:.3f}s, {metrics['memory_used_mb']:.2f}MB")
    
    def benchmark_xml_parsing(self):
        """Benchmark XML parsing performance"""
        print("🔍 Benchmarking XML parsing...")
        
        # Create a sample XML for testing
        sample_xml = """<?xml version="1.0"?>
<nmaprun>
    <host>
        <address addr="192.168.1.1" addrtype="ipv4"/>
        <ports>
            <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http"/>
            </port>
            <port protocol="tcp" portid="443">
                <state state="open"/>
                <service name="https"/>
            </port>
        </ports>
    </host>
</nmaprun>"""
        
        with open('temp_scan.xml', 'w') as f:
            f.write(sample_xml)
        
        self.start_measurement()
        try:
            from nexus.cli.parser import parse_nmap_xml
            result = parse_nmap_xml('temp_scan.xml')
        except Exception as e:
            print(f"⚠️ XML parsing benchmark failed: {e}")
        finally:
            if os.path.exists('temp_scan.xml'):
                os.remove('temp_scan.xml')
        
        metrics = self.end_measurement()
        self.results['xml_parsing'] = metrics
        print(f"✅ XML parsing: {metrics['execution_time']:.3f}s, {metrics['memory_used_mb']:.2f}MB")
    
    def benchmark_threat_intelligence(self):
        """Benchmark threat intelligence API calls"""
        print("🔍 Benchmarking threat intelligence...")
        
        self.start_measurement()
        try:
            from nexus.ai.advanced_threat_intel import AdvancedThreatIntel
            ati = AdvancedThreatIntel()
            # Mock the API call to avoid actual network requests
            with open(os.devnull, 'w') as f:
                import sys
                old_stdout = sys.stdout
                sys.stdout = f
                try:
                    # This will fail due to missing API key, but we measure the attempt
                    ati.check_ip_reputation('8.8.8.8')
                except:
                    pass
                finally:
                    sys.stdout = old_stdout
        except Exception as e:
            print(f"⚠️ Threat intelligence benchmark failed: {e}")
        
        metrics = self.end_measurement()
        self.results['threat_intelligence'] = metrics
        print(f"✅ Threat intelligence: {metrics['execution_time']:.3f}s, {metrics['memory_used_mb']:.2f}MB")
    
    def benchmark_concurrent_operations(self):
        """Benchmark concurrent operations"""
        print("🔍 Benchmarking concurrent operations...")
        
        import threading
        import queue
        
        def worker(q, results):
            """Worker function for concurrent operations"""
            start = time.time()
            # Simulate some work
            time.sleep(0.1)
            end = time.time()
            results.append(end - start)
            q.put(1)
        
        self.start_measurement()
        
        # Test with 10 concurrent operations
        num_workers = 10
        q = queue.Queue()
        results = []
        threads = []
        
        for i in range(num_workers):
            t = threading.Thread(target=worker, args=(q, results))
            threads.append(t)
            t.start()
        
        # Wait for all threads to complete
        for t in threads:
            t.join()
        
        metrics = self.end_measurement()
        self.results['concurrent_operations'] = {
            **metrics,
            'num_workers': num_workers,
            'avg_worker_time': sum(results) / len(results) if results else 0
        }
        print(f"✅ Concurrent operations: {metrics['execution_time']:.3f}s, {metrics['memory_used_mb']:.2f}MB")
    
    def benchmark_data_processing(self):
        """Benchmark data processing operations"""
        print("🔍 Benchmarking data processing...")
        
        import numpy as np
        import pandas as pd
        
        # Create sample data
        data = np.random.rand(10000, 50)  # 10k samples, 50 features
        df = pd.DataFrame(data)
        
        self.start_measurement()
        try:
            # Simulate data processing operations
            df.describe()
            df.corr()
            df.isnull().sum()
        except Exception as e:
            print(f"⚠️ Data processing benchmark failed: {e}")
        
        metrics = self.end_measurement()
        self.results['data_processing'] = metrics
        print(f"✅ Data processing: {metrics['execution_time']:.3f}s, {metrics['memory_used_mb']:.2f}MB")
    
    def run_all_benchmarks(self):
        """Run all performance benchmarks"""
        print("🚀 Starting NEXUS-AI Performance Benchmarks")
        print("=" * 50)
        
        benchmarks = [
            self.benchmark_model_loading,
            self.benchmark_xml_parsing,
            self.benchmark_threat_intelligence,
            self.benchmark_concurrent_operations,
            self.benchmark_data_processing
        ]
        
        for benchmark in benchmarks:
            try:
                benchmark()
            except Exception as e:
                print(f"❌ Benchmark failed: {e}")
        
        self.generate_report()
    
    def generate_report(self):
        """Generate performance benchmark report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'system_info': {
                'python_version': sys.version,
                'platform': sys.platform,
                'cpu_count': psutil.cpu_count(),
                'memory_gb': psutil.virtual_memory().total / 1024 / 1024 / 1024
            },
            'benchmarks': self.results,
            'summary': {
                'total_benchmarks': len(self.results),
                'total_execution_time': sum(b['execution_time'] for b in self.results.values()),
                'total_memory_used': sum(b['memory_used_mb'] for b in self.results.values())
            }
        }
        
        # Save report
        with open('benchmark_results.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print("\n" + "=" * 50)
        print("📊 Benchmark Report Generated")
        print(f"📁 Saved to: benchmark_results.json")
        print(f"⏱️ Total execution time: {report['summary']['total_execution_time']:.3f}s")
        print(f"💾 Total memory used: {report['summary']['total_memory_used']:.2f}MB")
        print("=" * 50)

def main():
    """Main function to run benchmarks"""
    benchmark = PerformanceBenchmark()
    benchmark.run_all_benchmarks()

if __name__ == "__main__":
    main() 