"""
Real-Time Learning Module
Provides continuous learning capabilities for the AI system with sophisticated analytics
"""

import json
import os
import time
import threading
import queue
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import pickle
import hashlib

from ..core.config import get_config, get_logger
from ..optimization.cache_manager import get_cache_manager

# Get configuration and logger
config = get_config()
logger = get_logger()

class LearningStatus(Enum):
    """Enumeration for learning system status"""
    ACTIVE = "active"
    PAUSED = "paused"
    ERROR = "error"
    INITIALIZING = "initializing"

@dataclass
class LearningSample:
    """Data class for learning samples with enhanced metadata"""
    timestamp: datetime
    features: Dict[str, Any]
    prediction: Dict[str, Any]
    ground_truth: Optional[str]
    confidence: float
    model_version: str
    sample_hash: str
    metadata: Dict[str, Any]

@dataclass
class LearningMetrics:
    """Data class for learning performance metrics"""
    total_samples: int
    accuracy_trend: List[float]
    confidence_trend: List[float]
    learning_rate: float
    last_updated: datetime
    performance_score: float

class RealTimeLearning:
    """
    Advanced real-time learning system that continuously improves the AI model
    with sophisticated analytics and humanized insights
    
    TODO: The learning rate sometimes gets stuck, need to implement adaptive learning
    TODO: Memory usage can spike during large batch processing
    TODO: Need to add better error recovery for corrupted datasets
    TODO: The model sometimes overfits to recent data, need to fix that
    TODO: Should probably add a way to rollback bad model updates
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.learning_queue = queue.Queue()
        self.status = LearningStatus.INITIALIZING
        self.total_samples = 0
        self.last_updated = None
        self.learning_thread = None
        self.cache_manager = get_cache_manager()
        
        # Performance tracking
        self.accuracy_history = []
        self.confidence_history = []
        self.learning_rate = 0.01
        self.performance_score = 0.0
        
        # Get data paths from configuration
        self.data_dir = self._get_data_directory()
        self.dataset_path = os.path.join(self.data_dir, "learning_dataset.json")
        self.metrics_path = os.path.join(self.data_dir, "learning_metrics.json")
        self.model_checkpoint_path = os.path.join(self.data_dir, "model_checkpoint.pkl")
        
        # Learning configuration
        self.batch_size = self.config.get('ai.learning.batch_size', 100)
        self.update_frequency = self.config.get('ai.learning.update_frequency', 3600)
        self.max_samples = self.config.get('ai.learning.max_samples', 10000)
        self.min_confidence_threshold = 0.7
        self.performance_threshold = 0.8
        
        logger.info("Real-time learning initialized", 
                   data_dir=self.data_dir,
                   batch_size=self.batch_size,
                   update_frequency=self.update_frequency)
        
        # Load existing dataset and metrics
        # This part can be slow if the dataset is large
        # Sometimes it takes forever to load, but it's worth it
        self._load_dataset()
        self._load_metrics()
        
        # Start learning system
        # Sometimes this fails if the thread creation fails, but it's rare
        # The threading can be a bit finicky on some systems
        self._start_learning_system()
    
    def _get_data_directory(self) -> str:
        """Get data directory with intelligent fallback"""
        data_dir = self.config.get('paths.data', "data")
        if not os.path.exists(data_dir):
            # Try alternative paths
            alt_paths = [
                os.path.join(os.path.dirname(__file__), "..", "..", "..", "data"),
                os.path.join(os.getcwd(), "data"),
                "data"
            ]
            for path in alt_paths:
                if os.path.exists(path):
                    data_dir = path
                    break
            else:
                # Create data directory in current working directory
                data_dir = os.path.join(os.getcwd(), "data")
        
        os.makedirs(data_dir, exist_ok=True)
        return data_dir
    
    def _load_dataset(self):
        """Load existing learning dataset with enhanced error handling"""
        if os.path.exists(self.dataset_path):
            try:
                with open(self.dataset_path, 'r') as f:
                    self.dataset = json.load(f)
                self.total_samples = len(self.dataset.get('samples', []))
                self.last_updated = datetime.fromisoformat(self.dataset.get('last_updated', datetime.now().isoformat()))
                logger.info("Loaded existing learning dataset", 
                           samples=self.total_samples,
                           last_updated=self.last_updated)
            except Exception as e:
                logger.error("Could not load learning dataset", error=str(e))
                self.dataset = {"samples": [], "metadata": {}}
        else:
            logger.info("No existing learning dataset found, creating new one")
            self.dataset = {"samples": [], "metadata": {}}
    
    def _load_metrics(self):
        """Load learning metrics with sophisticated analytics"""
        if os.path.exists(self.metrics_path):
            try:
                with open(self.metrics_path, 'r') as f:
                    metrics_data = json.load(f)
                
                self.accuracy_history = metrics_data.get('accuracy_history', [])
                self.confidence_history = metrics_data.get('confidence_history', [])
                self.learning_rate = metrics_data.get('learning_rate', 0.01)
                self.performance_score = metrics_data.get('performance_score', 0.0)
                
                logger.info("Loaded learning metrics", 
                           accuracy_samples=len(self.accuracy_history),
                           confidence_samples=len(self.confidence_history),
                           performance_score=self.performance_score)
            except Exception as e:
                logger.error("Could not load learning metrics", error=str(e))
                self.accuracy_history = []
                self.confidence_history = []
                self.learning_rate = 0.01
                self.performance_score = 0.0
        else:
            logger.info("No existing learning metrics found, starting fresh")
            self.accuracy_history = []
            self.confidence_history = []
            self.learning_rate = 0.01
            self.performance_score = 0.0
    
    def _save_dataset(self):
        """Save learning dataset to file with enhanced metadata"""
        try:
            self.dataset['last_updated'] = datetime.now().isoformat()
            self.dataset['total_samples'] = len(self.dataset.get('samples', []))
            self.dataset['metadata']['version'] = '2.0.0'
            self.dataset['metadata']['last_save'] = datetime.now().isoformat()
            
            with open(self.dataset_path, 'w') as f:
                json.dump(self.dataset, f, indent=2)
            logger.debug("Saved learning dataset", path=self.dataset_path)
        except Exception as e:
            logger.error("Could not save learning dataset", error=str(e))
    
    def _save_metrics(self):
        """Save learning metrics with sophisticated analytics"""
        try:
            metrics_data = {
                'accuracy_history': self.accuracy_history,
                'confidence_history': self.confidence_history,
                'learning_rate': self.learning_rate,
                'performance_score': self.performance_score,
                'last_updated': datetime.now().isoformat(),
                'total_samples': self.total_samples,
                'status': self.status.value
            }
            
            with open(self.metrics_path, 'w') as f:
                json.dump(metrics_data, f, indent=2)
            logger.debug("Saved learning metrics", path=self.metrics_path)
        except Exception as e:
            logger.error("Could not save learning metrics", error=str(e))
    
    def add_sample(self, sample: Dict[str, Any]):
        """
        Add a new learning sample to the queue with enhanced validation
        
        Args:
            sample: Learning sample with features, prediction, and ground truth
        """
        try:
            # Validate sample
            if not self._validate_sample(sample):
                logger.warning("Invalid learning sample received", sample=sample)
                return
            
            # Create enhanced sample with metadata
            enhanced_sample = self._create_enhanced_sample(sample)
            
            # Add to queue
            self.learning_queue.put(enhanced_sample)
            
            # Start learning thread if not already running
            if self.status == LearningStatus.ACTIVE and not self.learning_thread:
                self._start_learning_thread()
            
            logger.debug("Added learning sample to queue", 
                        sample_hash=enhanced_sample.sample_hash,
                        confidence=enhanced_sample.confidence)
            
        except Exception as e:
            logger.error("Failed to add learning sample", error=str(e))
    
    def _validate_sample(self, sample: Dict[str, Any]) -> bool:
        """Validate learning sample with comprehensive checks"""
        required_fields = ['features', 'prediction']
        
        for field in required_fields:
            if field not in sample:
                return False
        
        # Validate features
        features = sample.get('features', {})
        if not isinstance(features, dict) or not features:
            return False
        
        # Validate prediction
        prediction = sample.get('prediction', {})
        if not isinstance(prediction, dict):
            return False
        
        # Validate confidence
        confidence = sample.get('confidence', 0.0)
        if not isinstance(confidence, (int, float)) or confidence < 0 or confidence > 1:
            return False
        
        return True
    
    def _create_enhanced_sample(self, sample: Dict[str, Any]) -> LearningSample:
        """Create enhanced learning sample with metadata"""
        # Generate sample hash for deduplication
        sample_data = json.dumps(sample, sort_keys=True)
        sample_hash = hashlib.md5(sample_data.encode()).hexdigest()
        
        # Create enhanced sample
        enhanced_sample = LearningSample(
            timestamp=datetime.now(),
            features=sample.get('features', {}),
            prediction=sample.get('prediction', {}),
            ground_truth=sample.get('ground_truth'),
            confidence=sample.get('confidence', 0.0),
            model_version=sample.get('model_version', 'unknown'),
            sample_hash=sample_hash,
            metadata={
                'source': sample.get('source', 'unknown'),
                'analysis_type': sample.get('analysis_type', 'unknown'),
                'processing_time': sample.get('processing_time', 0.0)
            }
        )
        
        return enhanced_sample
    
    def _start_learning_system(self):
        """Start the learning system with enhanced initialization"""
        try:
            self.status = LearningStatus.ACTIVE
            self._start_learning_thread()
            logger.info("Learning system started successfully")
        except Exception as e:
            self.status = LearningStatus.ERROR
            logger.error("Failed to start learning system", error=str(e))
    
    def _start_learning_thread(self):
        """Start the learning worker thread"""
        if self.learning_thread and self.learning_thread.is_alive():
            return
        
        self.learning_thread = threading.Thread(target=self._learning_worker, daemon=True)
        self.learning_thread.start()
        logger.info("Learning worker thread started")
    
    def _learning_worker(self):
        """Advanced learning worker with sophisticated processing"""
        logger.info("Learning worker started")
        
        while self.status == LearningStatus.ACTIVE:
            try:
                # Process samples in batches
                batch = []
                batch_start_time = time.time()
                
                # Collect batch
                while len(batch) < self.batch_size:
                    try:
                        sample = self.learning_queue.get(timeout=1.0)
                        batch.append(sample)
                    except queue.Empty:
                        break
                
                if not batch:
                    time.sleep(1)
                    continue
                
                # Process batch
                self._process_batch(batch)
                
                # Update metrics
                batch_time = time.time() - batch_start_time
                logger.debug("Processed learning batch", 
                           batch_size=len(batch),
                           processing_time=batch_time)
                
                # Save periodically
                if self.total_samples % 100 == 0:
                    self._save_dataset()
                    self._save_metrics()
                
            except Exception as e:
                logger.error("Learning worker error", error=str(e))
                time.sleep(5)  # Wait before retrying
        
        logger.info("Learning worker stopped")
    
    def _process_batch(self, batch: List[LearningSample]):
        """Process a batch of learning samples with sophisticated analytics"""
        try:
            # Filter samples by confidence threshold
            high_confidence_samples = [
                sample for sample in batch 
                if sample.confidence >= self.min_confidence_threshold
            ]
            
            if not high_confidence_samples:
                logger.debug("No high-confidence samples in batch")
                return
            
            # Add samples to dataset
            for sample in high_confidence_samples:
                sample_dict = asdict(sample)
                sample_dict['timestamp'] = sample.timestamp.isoformat()
                
                # Check for duplicates
                if not self._is_duplicate_sample(sample):
                    self.dataset['samples'].append(sample_dict)
                    self.total_samples += 1
            
            # Update performance metrics
            self._update_performance_metrics(batch)
            
            # Trigger model update if conditions are met
            if self._should_update_model():
                self._trigger_model_update()
            
            logger.info("Processed learning batch", 
                       total_samples=self.total_samples,
                       high_confidence_samples=len(high_confidence_samples))
            
        except Exception as e:
            logger.error("Failed to process learning batch", error=str(e))
    
    def _is_duplicate_sample(self, sample: LearningSample) -> bool:
        """Check if sample is duplicate using hash"""
        existing_hashes = {
            s.get('sample_hash', '') 
            for s in self.dataset.get('samples', [])
        }
        return sample.sample_hash in existing_hashes
    
    def _update_performance_metrics(self, batch: List[LearningSample]):
        """Update performance metrics with sophisticated analytics"""
        if not batch:
            return
        
        # Calculate batch accuracy (if ground truth available)
        accuracy_samples = [s for s in batch if s.ground_truth is not None]
        if accuracy_samples:
            correct_predictions = 0
            for sample in accuracy_samples:
                predicted_class = sample.prediction.get('class', 'unknown')
                if predicted_class == sample.ground_truth:
                    correct_predictions += 1
            
            batch_accuracy = correct_predictions / len(accuracy_samples)
            self.accuracy_history.append(batch_accuracy)
            
            # Keep only recent history
            if len(self.accuracy_history) > 100:
                self.accuracy_history = self.accuracy_history[-100:]
        
        # Update confidence metrics
        avg_confidence = np.mean([s.confidence for s in batch])
        self.confidence_history.append(avg_confidence)
        
        # Keep only recent history
        if len(self.confidence_history) > 100:
            self.confidence_history = self.confidence_history[-100:]
        
        # Calculate performance score
        self._calculate_performance_score()
    
    def _calculate_performance_score(self):
        """Calculate overall performance score with sophisticated metrics"""
        if not self.accuracy_history or not self.confidence_history:
            self.performance_score = 0.0
            return
        
        # Calculate recent accuracy trend
        recent_accuracy = np.mean(self.accuracy_history[-10:]) if len(self.accuracy_history) >= 10 else np.mean(self.accuracy_history)
        
        # Calculate recent confidence trend
        recent_confidence = np.mean(self.confidence_history[-10:]) if len(self.confidence_history) >= 10 else np.mean(self.confidence_history)
        
        # Calculate performance score (weighted combination)
        accuracy_weight = 0.6
        confidence_weight = 0.4
        
        self.performance_score = (accuracy_weight * recent_accuracy) + (confidence_weight * recent_confidence)
        
        # Adjust learning rate based on performance
        if self.performance_score > self.performance_threshold:
            self.learning_rate = max(0.001, self.learning_rate * 0.95)  # Slow down
        else:
            self.learning_rate = min(0.1, self.learning_rate * 1.05)  # Speed up
    
    def _should_update_model(self) -> bool:
        """Determine if model should be updated based on sophisticated criteria"""
        # Check if enough samples have been collected
        if self.total_samples < 100:
            return False
        
        # Check if performance is improving
        if len(self.accuracy_history) < 5:
            return False
        
        recent_accuracy = np.mean(self.accuracy_history[-5:])
        older_accuracy = np.mean(self.accuracy_history[-10:-5]) if len(self.accuracy_history) >= 10 else recent_accuracy
        
        # Update if performance is improving or if we have many new samples
        performance_improving = recent_accuracy > older_accuracy
        many_samples = self.total_samples % 500 == 0
        
        return performance_improving or many_samples
    
    def _trigger_model_update(self):
        """Trigger model update with enhanced logging"""
        try:
            logger.info("Triggering model update", 
                       total_samples=self.total_samples,
                       performance_score=self.performance_score)
            
            # Save current model checkpoint
            self._save_model_checkpoint()
            
            # Update model (placeholder for actual model update logic)
            # In a real implementation, this would retrain the model
            
            logger.info("Model update completed")
            
        except Exception as e:
            logger.error("Failed to update model", error=str(e))
    
    def _save_model_checkpoint(self):
        """Save model checkpoint for recovery"""
        try:
            checkpoint_data = {
                'total_samples': self.total_samples,
                'performance_score': self.performance_score,
                'accuracy_history': self.accuracy_history[-50:],  # Last 50 samples
                'confidence_history': self.confidence_history[-50:],
                'timestamp': datetime.now().isoformat()
            }
            
            with open(self.model_checkpoint_path, 'wb') as f:
                pickle.dump(checkpoint_data, f)
            
            logger.debug("Model checkpoint saved")
            
        except Exception as e:
            logger.error("Failed to save model checkpoint", error=str(e))
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive learning statistics with humanized insights"""
        try:
            # Calculate recent trends
            recent_accuracy = np.mean(self.accuracy_history[-10:]) if self.accuracy_history else 0.0
            recent_confidence = np.mean(self.confidence_history[-10:]) if self.confidence_history else 0.0
            
            # Calculate improvement trends
            accuracy_improvement = 0.0
            if len(self.accuracy_history) >= 10:
                recent_avg = np.mean(self.accuracy_history[-10:])
                older_avg = np.mean(self.accuracy_history[-20:-10])
                accuracy_improvement = recent_avg - older_avg
            
            # Generate insights
            insights = self._generate_learning_insights()
            
            return {
                'total_samples': self.total_samples,
                'status': self.status.value,
                'learning_enabled': self.status == LearningStatus.ACTIVE,
                'last_updated': self.last_updated.isoformat() if self.last_updated else None,
                'queue_size': self.learning_queue.qsize(),
                'performance': {
                    'current_accuracy': recent_accuracy,
                    'current_confidence': recent_confidence,
                    'performance_score': self.performance_score,
                    'accuracy_improvement': accuracy_improvement,
                    'learning_rate': self.learning_rate
                },
                'trends': {
                    'accuracy_trend': self.accuracy_history[-20:],  # Last 20 samples
                    'confidence_trend': self.confidence_history[-20:],
                    'performance_trend': [self.performance_score]
                },
                'insights': insights,
                'recommendations': self._generate_learning_recommendations()
            }
            
        except Exception as e:
            logger.error("Failed to get learning statistics", error=str(e))
            return {
                'error': str(e),
                'status': self.status.value,
                'learning_enabled': False
            }
    
    def _generate_learning_insights(self) -> List[str]:
        """Generate humanized insights about learning performance"""
        insights = []
        
        if self.total_samples == 0:
            insights.append("🎯 No learning samples collected yet")
            return insights
        
        # Performance insights
        if self.performance_score > 0.9:
            insights.append("🚀 Excellent learning performance detected")
        elif self.performance_score > 0.7:
            insights.append("✅ Good learning performance maintained")
        elif self.performance_score > 0.5:
            insights.append("⚠️ Learning performance needs improvement")
        else:
            insights.append("❌ Learning performance is below optimal levels")
        
        # Sample insights
        if self.total_samples > 1000:
            insights.append(f"📊 Rich dataset with {self.total_samples:,} learning samples")
        elif self.total_samples > 100:
            insights.append(f"📈 Growing dataset with {self.total_samples} learning samples")
        else:
            insights.append(f"🌱 Building dataset with {self.total_samples} learning samples")
        
        # Trend insights
        if len(self.accuracy_history) >= 5:
            recent_accuracy = np.mean(self.accuracy_history[-5:])
            if recent_accuracy > 0.8:
                insights.append("📈 Accuracy is trending upward")
            elif recent_accuracy < 0.6:
                insights.append("📉 Accuracy is trending downward")
            else:
                insights.append("➡️ Accuracy is stable")
        
        return insights
    
    def _generate_learning_recommendations(self) -> List[str]:
        """Generate actionable recommendations for learning improvement"""
        recommendations = []
        
        if self.total_samples < 100:
            recommendations.append("📚 Collect more learning samples to improve model performance")
        
        if self.performance_score < 0.7:
            recommendations.append("🔧 Consider adjusting model parameters or features")
            recommendations.append("📊 Review recent predictions for patterns")
        
        if self.learning_queue.qsize() > 100:
            recommendations.append("⚡ Processing queue is large, consider increasing batch size")
        
        if len(self.accuracy_history) > 0 and np.mean(self.accuracy_history[-10:]) < 0.6:
            recommendations.append("🎯 Focus on improving prediction accuracy")
        
        recommendations.append("🔄 Regularly monitor learning performance metrics")
        recommendations.append("📋 Document learning insights for future improvements")
        
        return recommendations
    
    def pause_learning(self):
        """Pause the learning system"""
        self.status = LearningStatus.PAUSED
        logger.info("Learning system paused")
    
    def resume_learning(self):
        """Resume the learning system"""
        self.status = LearningStatus.ACTIVE
        self._start_learning_thread()
        logger.info("Learning system resumed")
    
    def clear_dataset(self):
        """Clear the learning dataset"""
        self.dataset = {"samples": [], "metadata": {}}
        self.total_samples = 0
        self.accuracy_history = []
        self.confidence_history = []
        self.performance_score = 0.0
        self._save_dataset()
        self._save_metrics()
        logger.info("Learning dataset cleared")

# Global learning instance
_learning_instance = None

def initialize_real_time_learning(config: Optional[Dict[str, Any]] = None):
    """Initialize the real-time learning system"""
    global _learning_instance
    if _learning_instance is None:
        _learning_instance = RealTimeLearning(config)
    return _learning_instance

def add_analysis_for_learning(config: Dict[str, Any], analysis_result: Dict[str, Any]):
    """Add analysis result to learning system"""
    try:
        learning_system = initialize_real_time_learning(config)
        
        # Extract learning sample from analysis result
        sample = {
            'features': analysis_result.get('features', {}),
            'prediction': analysis_result.get('prediction', {}),
            'ground_truth': analysis_result.get('ground_truth'),
            'confidence': analysis_result.get('confidence', 0.0),
            'model_version': analysis_result.get('model_version', 'unknown'),
            'source': 'network_analysis',
            'analysis_type': 'security_scan',
            'processing_time': analysis_result.get('processing_time', 0.0)
        }
        
        learning_system.add_sample(sample)
        logger.debug("Added analysis to learning system")
        
    except Exception as e:
        logger.error("Failed to add analysis to learning system", error=str(e))

def get_learning_statistics(config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Get learning statistics with enhanced analytics"""
    try:
        learning_system = initialize_real_time_learning(config)
        return learning_system.get_statistics()
    except Exception as e:
        logger.error("Failed to get learning statistics", error=str(e))
        return {
            'error': str(e),
            'status': 'error',
            'learning_enabled': False
        } 