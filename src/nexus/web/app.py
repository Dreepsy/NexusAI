#!/usr/bin/env python3
"""
NEXUS-AI Advanced Web Interface
Provides a modern, sophisticated web UI for network security analysis

TODO: The WebSocket connection sometimes drops on slow networks
TODO: Need to add better error handling for large file uploads
TODO: The session management could be more robust
TODO: The progress bar sometimes gets stuck, need to fix that
TODO: Should probably add a file size limit for uploads
"""

from flask import Flask, render_template, request, jsonify, send_file, session
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import os
import json
import base64
from datetime import datetime, timedelta
import tempfile
import threading
import time
from pathlib import Path

# Add parent directory to path
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from nexus.cli.commands import NexusAICLI
from nexus.core.config import get_config
from nexus.security.security_validator_enhanced import get_security_validator
from nexus.monitoring.health_check import get_health_monitor
from nexus.optimization.cache_manager import get_cache_manager

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('NEXUS_SECRET_KEY', 'nexus-ai-secret-key-2024')
app.config['SESSION_TYPE'] = 'filesystem'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Get configuration and services
config = get_config()
security_validator = get_security_validator()
health_monitor = get_health_monitor()
cache_manager = get_cache_manager()
cli = NexusAICLI()

# Session management
@app.before_request
def before_request():
    """Initialize session and perform security checks"""
    # This is a bit hacky but it works for now
    # TODO: Should probably implement proper user management
    if 'user_id' not in session:
        session['user_id'] = f"user_{int(time.time())}"
    if 'last_activity' not in session:
        session['last_activity'] = datetime.now().isoformat()

@app.route('/')
def index():
    """Main dashboard page with enhanced features"""
    try:
        # Get system status
        health_status = health_monitor.run_comprehensive_check()
        cache_stats = cache_manager.get_stats()
        
        # Get recent analyses from cache
        recent_analyses = []
        try:
            cache_keys = cache_manager.get_cache_keys()
            for key in cache_keys[:5]:  # Get last 5 analyses
                if key.startswith('scan_analysis_'):
                    analysis = cache_manager.get(key)
                    if analysis:
                        recent_analyses.append({
                            'timestamp': analysis.get('metadata', {}).get('timestamp', ''),
                            'filename': analysis.get('metadata', {}).get('scan_file', ''),
                            'risk_level': analysis.get('summary', {}).get('risk_level', 'UNKNOWN')
                        })
        except Exception as e:
            app.logger.warning(f"Could not retrieve recent analyses: {e}")
        
        return render_template('index.html', 
                            health_status=health_status,
                            cache_stats=cache_stats,
                            recent_analyses=recent_analyses,
                            config=config.config)
    except Exception as e:
        app.logger.error(f"Error loading dashboard: {e}")
        return render_template('error.html', error=str(e))

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """Enhanced API endpoint for scan analysis with real-time updates"""
    try:
        # Validate request
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Enhanced file validation
        validation_result = security_validator.validate_file_path(file.filename)
        if not validation_result['valid']:
            return jsonify({'error': f"File validation failed: {validation_result['errors']}"}), 400
        
        # Save file temporarily with enhanced security
        with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as tmp_file:
            file.save(tmp_file.name)
            tmp_path = tmp_file.name
        
        try:
            # Get analysis options
            options = request.form.get('options', '{}')
            options = json.loads(options)
            
            # Start analysis with progress updates
            def analyze_with_progress():
                try:
                    # Emit progress updates
                    socketio.emit('analysis_progress', {
                        'status': 'started',
                        'message': 'Starting analysis...',
                        'progress': 10
                    })
                    
                    # Perform analysis
                    result = cli.analyze_network_scan(tmp_path, output_format="json")
                    
                    socketio.emit('analysis_progress', {
                        'status': 'completed',
                        'message': 'Analysis completed successfully',
                        'progress': 100,
                        'result': result
                    })
                    
                except Exception as e:
                    socketio.emit('analysis_progress', {
                        'status': 'error',
                        'message': f'Analysis failed: {str(e)}',
                        'progress': 0
                    })
            
            # Run analysis in background thread
            thread = threading.Thread(target=analyze_with_progress)
            thread.start()
            
            return jsonify({
                'status': 'started',
                'message': 'Analysis started in background',
                'session_id': session['user_id']
            })
            
        finally:
            # Clean up temporary file
            try:
                os.unlink(tmp_path)
            except Exception as e:
                app.logger.warning(f"Could not clean up temporary file: {e}")
    
    except Exception as e:
        app.logger.error(f"Analysis API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze-sync', methods=['POST'])
def api_analyze_sync():
    """Synchronous analysis endpoint for immediate results"""
    try:
        # Validate request
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Enhanced file validation
        validation_result = security_validator.validate_file_path(file.filename)
        if not validation_result['valid']:
            return jsonify({'error': f"File validation failed: {validation_result['errors']}"}), 400
        
        # Save file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as tmp_file:
            file.save(tmp_file.name)
            tmp_path = tmp_file.name
        
        try:
            # Get analysis options
            options = request.form.get('options', '{}')
            options = json.loads(options)
            
            # Perform analysis
            result = cli.analyze_network_scan(tmp_path, output_format="json")
            
            # Add metadata
            result['metadata']['filename'] = file.filename
            result['metadata']['upload_time'] = datetime.now().isoformat()
            result['metadata']['file_size'] = os.path.getsize(tmp_path)
            result['metadata']['session_id'] = session['user_id']
            
            return jsonify(result)
            
        finally:
            # Clean up temporary file
            try:
                os.unlink(tmp_path)
            except Exception as e:
                app.logger.warning(f"Could not clean up temporary file: {e}")
    
    except Exception as e:
        app.logger.error(f"Sync analysis API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze-with-exploits', methods=['POST'])
def api_analyze_with_exploits():
    """Enhanced API endpoint for scan analysis with exploit generation"""
    try:
        # Validate request
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Enhanced file validation
        validation_result = security_validator.validate_file_path(file.filename)
        if not validation_result['valid']:
            return jsonify({'error': f"File validation failed: {validation_result['errors']}"}), 400
        
        # Save file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as tmp_file:
            file.save(tmp_file.name)
            tmp_path = tmp_file.name
        
        try:
            # Get analysis options
            options = request.form.get('options', '{}')
            options = json.loads(options)
            
            # Perform analysis with exploit generation
            result = cli.analyze_network_scan_with_exploits(tmp_path, output_format="json")
            
            # Add metadata
            result['metadata'] = {
                'filename': file.filename,
                'upload_time': datetime.now().isoformat(),
                'file_size': os.path.getsize(tmp_path),
                'session_id': session['user_id']
            }
            
            return jsonify(result)
            
        finally:
            # Clean up temporary file
            try:
                os.unlink(tmp_path)
            except Exception as e:
                app.logger.warning(f"Could not clean up temporary file: {e}")
    
    except Exception as e:
        app.logger.error(f"Exploit analysis API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/health')
def api_health():
    """Enhanced health check endpoint"""
    try:
        health_status = health_monitor.run_comprehensive_check()
        cache_stats = cache_manager.get_stats()
        
        return jsonify({
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'health': health_status,
            'cache': cache_stats,
            'session': {
                'user_id': session.get('user_id'),
                'last_activity': session.get('last_activity')
            }
        })
    except Exception as e:
        app.logger.error(f"Health check error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/config')
def api_config():
    """Get configuration information"""
    try:
        # Return safe configuration (exclude sensitive data)
        safe_config = {
            'app': config.get('app', {}),
            'paths': config.get('paths', {}),
            'ai': {
                'model': config.get('ai.model', {}),
                'learning': config.get('ai.learning', {})
            },
            'security': {
                'validation': config.get('security.validation', {}),
                'encryption': config.get('security.encryption', {})
            },
            'performance': config.get('performance', {}),
            'monitoring': config.get('monitoring', {}),
            'web': config.get('web', {})
        }
        
        return jsonify(safe_config)
    except Exception as e:
        app.logger.error(f"Config API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/validate-file', methods=['POST'])
def api_validate_file():
    """Enhanced file validation endpoint"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Comprehensive file validation
        validation_result = security_validator.validate_file_path(file.filename)
        
        # Additional checks
        file_size = len(file.read())
        file.seek(0)  # Reset file pointer
        
        max_size = config.get('security.validation.max_file_size', '100MB')
        if isinstance(max_size, str):
            # Convert size string to bytes
            size_map = {'KB': 1024, 'MB': 1024**2, 'GB': 1024**3}
            for unit, multiplier in size_map.items():
                if max_size.upper().endswith(unit):
                    max_size = int(max_size[:-len(unit)]) * multiplier
                    break
        
        if file_size > max_size:
            validation_result['valid'] = False
            validation_result['errors'].append(f"File size ({file_size} bytes) exceeds maximum ({max_size} bytes)")
        
        return jsonify({
            'valid': validation_result['valid'],
            'errors': validation_result['errors'],
            'file_size': file_size,
            'filename': file.filename,
            'content_type': file.content_type
        })
    
    except Exception as e:
        app.logger.error(f"File validation error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/learning/stats')
def api_learning_stats():
    """Get AI learning statistics"""
    try:
        from nexus.ai.real_time_learning import get_learning_statistics
        stats = get_learning_statistics()
        return jsonify(stats)
    except Exception as e:
        app.logger.error(f"Learning stats error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/models/status')
def api_models_status():
    """Get AI model status and information"""
    try:
        from nexus.cli.predictor import get_model_info
        
        model_info = get_model_info()
        if model_info:
            return jsonify({
                'status': 'loaded',
                'model_info': model_info,
                'last_updated': datetime.now().isoformat()
            })
        else:
            return jsonify({
                'status': 'not_loaded',
                'message': 'No model found',
                'last_updated': datetime.now().isoformat()
            })
    except Exception as e:
        app.logger.error(f"Model status error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/cache/stats')
def api_cache_stats():
    """Get cache statistics"""
    try:
        stats = cache_manager.get_stats()
        return jsonify(stats)
    except Exception as e:
        app.logger.error(f"Cache stats error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/cache/clear', methods=['POST'])
def api_cache_clear():
    """Clear cache"""
    try:
        namespace = request.json.get('namespace', None)
        cache_manager.clear(namespace)
        return jsonify({'status': 'success', 'message': 'Cache cleared'})
    except Exception as e:
        app.logger.error(f"Cache clear error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat-intel/check-ips', methods=['POST'])
def api_threat_intel_check():
    """Check IP reputation using threat intelligence"""
    try:
        data = request.json
        ips = data.get('ips', [])
        
        if not ips:
            return jsonify({'error': 'No IPs provided'}), 400
        
        # Validate IPs
        for ip in ips:
            validation = security_validator.validate_and_sanitize_input(ip, "ip")
            if not validation['valid']:
                return jsonify({'error': f"Invalid IP: {ip}"}), 400
        
        # Get threat intelligence
        result = cli.threat_intel.aggregate_threat_feeds(ips)
        return jsonify(result)
    
    except Exception as e:
        app.logger.error(f"Threat intel error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat-intel/search-assets', methods=['POST'])
def api_search_assets():
    """Search for internet assets"""
    try:
        data = request.json
        query = data.get('query', '')
        
        if not query:
            return jsonify({'error': 'No query provided'}), 400
        
        # Validate query
        validation = security_validator.validate_and_sanitize_input(query, "text")
        if not validation['valid']:
            return jsonify({'error': f"Invalid query: {validation['errors']}"}), 400
        
        # Search assets
        result = cli.threat_intel.search_internet_assets(query)
        return jsonify(result)
    
    except Exception as e:
        app.logger.error(f"Asset search error: {e}")
        return jsonify({'error': str(e)}), 500

# WebSocket events
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('connected', {'message': 'Connected to NexusAI WebSocket'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    app.logger.info('Client disconnected')

@socketio.on('request_health_update')
def handle_health_update():
    """Send health update to client"""
    try:
        health_status = health_monitor.run_comprehensive_check()
        emit('health_update', health_status)
    except Exception as e:
        emit('health_update', {'error': str(e)})

# Error handlers
@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    app.logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(Exception)
def handle_exception(e):
    """Handle unhandled exceptions"""
    app.logger.error(f"Unhandled exception: {e}")
    return jsonify({'error': 'An unexpected error occurred'}), 500

if __name__ == '__main__':
    # Get configuration
    host = config.get('web.host', '0.0.0.0')
    port = config.get('web.port', 5000)
    debug = config.get('web.debug', False)
    
    print(f"🚀 Starting NexusAI Web Interface")
    print(f"🌐 Server: http://{host}:{port}")
    print(f"🔧 Debug Mode: {'Enabled' if debug else 'Disabled'}")
    print(f"🛡️  Security: {'Enabled' if config.get('security.validation.strict_mode') else 'Disabled'}")
    
    # Start the application
    socketio.run(app, host=host, port=port, debug=debug) 