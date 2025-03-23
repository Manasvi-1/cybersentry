import hashlib
import random
import json
import logging
import re
from datetime import datetime

def detect_deepfake(file_content, media_type):
    """
    Detects if the provided media is a deepfake
    This is a simplified simulation for demonstration purposes
    
    Args:
        file_content: Base64 content of the file
        media_type: Type of media (image, video, audio)
    
    Returns:
        (is_deepfake, confidence, features) tuple
    """
    try:
        # Log the detection attempt
        logging.info(f"Analyzing potential deepfake media of type: {media_type}")
        
        # Get first 100 chars of content to avoid logging large files
        content_preview = file_content[:100] + "..." if len(file_content) > 100 else file_content
        logging.debug(f"Content preview: {content_preview}")
        
        # For demo purposes, we'll analyze the hash of the content
        # In a real system, this would be actual media analysis
        file_hash = hashlib.sha256(file_content.encode()).hexdigest()
        
        # Extract some "features" from the hash
        # These are just simulated features for demonstration
        features = extract_features_from_hash(file_hash, media_type)
        
        # Detect if it's a deepfake based on features
        # In a real system, this would use an actual ML model
        is_deepfake, confidence = analyze_features(features, media_type)
        
        return is_deepfake, confidence, features
    
    except Exception as e:
        logging.error(f"Error detecting deepfake: {str(e)}")
        # Return conservative values in case of error
        return False, 0.0, {"error": str(e)}

def extract_features_from_hash(file_hash, media_type):
    """
    Extract simulated features from a file hash
    
    Args:
        file_hash: SHA-256 hash of the file
        media_type: Type of media (image, video, audio)
    
    Returns:
        Dictionary of features
    """
    # Convert hash segments to numbers for feature simulation
    segments = [file_hash[i:i+8] for i in range(0, len(file_hash), 8)]
    values = [int(segment, 16) / (16**8) for segment in segments]
    
    # Common features for all media types
    features = {
        "entropy": values[0] * 8,  # Normalized between 0-8
        "compression_artifacts": values[1] * 10,  # 0-10 scale
        "metadata_consistency": values[2] > 0.5,
        "digital_fingerprint": {
            "hash": file_hash[:16],
            "signature": "".join(random.choice("0123456789ABCDEF") for _ in range(12))
        }
    }
    
    # Media-specific features
    if media_type == "image":
        features.update({
            "facial_landmarks_consistency": values[3] * 10,  # 0-10 scale
            "eye_reflection_patterns": values[4] * 10,  # 0-10 scale
            "lighting_consistency": values[5] * 10,  # 0-10 scale
            "edge_detection_anomalies": values[6] * 10,  # 0-10 scale
            "texture_analysis": {
                "smoothness": values[7] * 10,
                "grain": (1 - values[7]) * 10,
                "unnatural_patterns": values[8] > 0.7
            }
        })
    
    elif media_type == "video":
        features.update({
            "temporal_consistency": values[3] * 10,  # 0-10 scale
            "face_movement_naturality": values[4] * 10,  # 0-10 scale
            "blinking_patterns": values[5] * 10,  # 0-10 scale
            "lip_sync_accuracy": values[6] * 10,  # 0-10 scale
            "frame_transition_analysis": {
                "smoothness": values[7] * 10,
                "artifacts": (1 - values[7]) * 10,
                "unnatural_movement": values[8] > 0.7
            }
        })
    
    elif media_type == "audio":
        features.update({
            "spectral_consistency": values[3] * 10,  # 0-10 scale
            "voice_naturalness": values[4] * 10,  # 0-10 scale
            "breathing_patterns": values[5] * 10,  # 0-10 scale
            "background_noise_coherence": values[6] * 10,  # 0-10 scale
            "frequency_analysis": {
                "harmonics": values[7] * 10,
                "unnatural_transitions": (1 - values[7]) * 10,
                "voice_synthesis_markers": values[8] > 0.7
            }
        })
    
    # Add timestamp for feature extraction
    features["analysis_timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    return features

def analyze_features(features, media_type):
    """
    Analyze features to determine if the media is a deepfake
    
    Args:
        features: Dictionary of extracted features
        media_type: Type of media (image, video, audio)
    
    Returns:
        (is_deepfake, confidence) tuple
    """
    # Calculate deepfake probability based on features
    if "error" in features:
        return False, 0.0
    
    # Start with base probability
    deepfake_probability = 0.0
    
    # Common features analysis
    if features["entropy"] < 4.0:
        deepfake_probability += 0.2
    
    if features["compression_artifacts"] > 7.0:
        deepfake_probability += 0.15
    
    if not features["metadata_consistency"]:
        deepfake_probability += 0.1
    
    # Media-specific analysis
    if media_type == "image":
        if features["facial_landmarks_consistency"] < 5.0:
            deepfake_probability += 0.2
        
        if features["eye_reflection_patterns"] < 4.0:
            deepfake_probability += 0.15
        
        if features["lighting_consistency"] < 4.0:
            deepfake_probability += 0.1
        
        if features["edge_detection_anomalies"] > 7.0:
            deepfake_probability += 0.1
        
        if features["texture_analysis"]["unnatural_patterns"]:
            deepfake_probability += 0.2
    
    elif media_type == "video":
        if features["temporal_consistency"] < 5.0:
            deepfake_probability += 0.2
        
        if features["face_movement_naturality"] < 4.0:
            deepfake_probability += 0.15
        
        if features["blinking_patterns"] < 4.0:
            deepfake_probability += 0.15
        
        if features["lip_sync_accuracy"] < 5.0:
            deepfake_probability += 0.2
        
        if features["frame_transition_analysis"]["unnatural_movement"]:
            deepfake_probability += 0.2
    
    elif media_type == "audio":
        if features["spectral_consistency"] < 5.0:
            deepfake_probability += 0.2
        
        if features["voice_naturalness"] < 4.0:
            deepfake_probability += 0.2
        
        if features["breathing_patterns"] < 3.0:
            deepfake_probability += 0.15
        
        if features["background_noise_coherence"] < 4.0:
            deepfake_probability += 0.1
        
        if features["frequency_analysis"]["voice_synthesis_markers"]:
            deepfake_probability += 0.25
    
    # Cap the probability at 0.95
    deepfake_probability = min(0.95, deepfake_probability)
    
    # Determine if it's a deepfake based on threshold
    is_deepfake = deepfake_probability >= 0.5
    
    return is_deepfake, deepfake_probability
