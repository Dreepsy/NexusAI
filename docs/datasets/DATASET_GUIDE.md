# Security Dataset Guide for NEXUS-AI

This guide provides comprehensive information about security datasets for training your AI models.

## 🎯 **Recommended Datasets (In Order of Preference)**

### **1. NSL-KDD Dataset** ⭐⭐⭐⭐⭐
**Best for beginners and general use**

- **Download**: https://www.unb.ca/cic/datasets/nsl.html
- **Size**: ~125MB
- **Records**: ~148,000
- **Features**: 41 features per record
- **Classes**: 5 attack types (DoS, Probe, R2L, U2R, Normal)
- **Format**: CSV/TXT
- **Why it's great**: Clean, balanced, widely used in research

**Quick Setup:**
```bash
# Download and place in data/nsl_kdd/
wget https://www.unb.ca/cic/datasets/nsl.html
# Extract and rename files to:
# - KDDTrain+.txt
# - KDDTest+.txt
```

### **2. UNSW-NB15 Dataset** ⭐⭐⭐⭐⭐
**Best for comprehensive analysis**

- **Download**: https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-NB15-Datasets/
- **Size**: ~45MB
- **Records**: ~2.5 million
- **Features**: 49 features
- **Classes**: 10 attack types (Normal, Generic, Exploits, Fuzzers, etc.)
- **Format**: CSV
- **Why it's great**: Modern, realistic, comprehensive attack types

**Quick Setup:**
```bash
# Download and place in data/unsw_nb15/
# - UNSW_NB15_training-set.csv
# - UNSW_NB15_testing-set.csv
```

### **3. CICIDS2017 Dataset** ⭐⭐⭐⭐
**Best for real-world scenarios**

- **Download**: https://www.unb.ca/cic/datasets/ids-2017.html
- **Size**: ~3GB
- **Records**: ~2.8 million
- **Features**: 78 features
- **Classes**: 8 attack types (Brute Force, Heartbleed, Bot, DDoS, etc.)
- **Format**: CSV
- **Why it's great**: Real-world traffic, recent attacks

### **4. CICIDS2018 Dataset** ⭐⭐⭐⭐
**Best for latest threats**

- **Download**: https://www.unb.ca/cic/datasets/ids-2018.html
- **Size**: ~6GB
- **Records**: ~17 million
- **Features**: 80 features
- **Classes**: 15 attack types
- **Format**: CSV
- **Why it's great**: Latest attacks, large scale

## 🔥 **Specialized Datasets**

### **5. Bot-IoT Dataset** ⭐⭐⭐⭐
**Best for IoT security**

- **Download**: https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-NB15-Datasets/
- **Size**: ~69GB
- **Records**: ~73 million
- **Focus**: IoT botnet attacks
- **Why it's great**: IoT-specific threats

### **6. ToN_IoT Dataset** ⭐⭐⭐⭐
**Best for Industrial IoT**

- **Download**: https://ieee-dataport.org/documents/toniot-datasets
- **Size**: ~16GB
- **Focus**: IoT and Industrial IoT attacks
- **Why it's great**: Industrial systems, IoT devices

### **7. CSE-CIC-IDS2018 Dataset** ⭐⭐⭐⭐
**Best for web application security**

- **Download**: https://www.unb.ca/cic/datasets/ids-2018.html
- **Size**: ~6GB
- **Focus**: Web attacks, DDoS, infiltration
- **Why it's great**: Web application security

## 📊 **Additional Resources**

### **8. MITRE ATT&CK Dataset**
- **Link**: https://attack.mitre.org/datasets/
- **Focus**: Attack techniques and procedures
- **Why it's great**: Real-world attack patterns

### **9. VirusTotal Dataset**
- **Link**: https://www.virustotal.com/gui/join-us
- **Focus**: Malware samples and analysis
- **Why it's great**: Real malware data

### **10. Shodan Dataset**
- **Link**: https://account.shodan.io/register
- **Focus**: Internet-wide scanning data
- **Why it's great**: Real network exposure data

## 🚀 **Quick Start with Sample Data**

The easiest way to get started is with the sample data that's already created:

```bash
# Sample data is already available in:
data/sample/KDDTrain+.txt  # 800 training samples
data/sample/KDDTest+.txt   # 200 test samples
```

## 📋 **Dataset Comparison**

| Dataset | Size | Records | Features | Classes | Difficulty | Best For |
|---------|------|---------|----------|---------|------------|----------|
| **Sample** | ~1MB | 1,000 | 41 | 5 | Beginner | Testing |
| **NSL-KDD** | ~125MB | 148K | 41 | 5 | Beginner | General use |
| **UNSW-NB15** | ~45MB | 2.5M | 49 | 10 | Intermediate | Comprehensive |
| **CICIDS2017** | ~3GB | 2.8M | 78 | 8 | Advanced | Real-world |
| **CICIDS2018** | ~6GB | 17M | 80 | 15 | Advanced | Latest threats |

## 🛠️ **Setup Instructions**

### **Step 1: Download Datasets**
```bash
# Run the dataset downloader
python3 scripts/download_datasets.py
```

### **Step 2: Manual Downloads**
For datasets that require manual download:

1. **NSL-KDD**: Visit https://www.unb.ca/cic/datasets/nsl.html
2. **UNSW-NB15**: Visit https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-NB15-Datasets/
3. **CICIDS2017**: Visit https://www.unb.ca/cic/datasets/ids-2017.html

### **Step 3: Update Configuration**
Add the following to your `config.yaml`:

```yaml
data_processing:
  datasets:
    sample:
      enabled: true
      path: "data/sample/KDDTrain+.txt"
      test_path: "data/sample/KDDTest+.txt"
      description: "Sample dataset for testing"
    
    nsl_kdd:
      enabled: true
      path: "data/nsl_kdd/KDDTrain+.txt"
      test_path: "data/nsl_kdd/KDDTest+.txt"
      description: "NSL-KDD dataset"
    
    unsw_nb15:
      enabled: true
      path: "data/unsw_nb15/UNSW_NB15_training-set.csv"
      test_path: "data/unsw_nb15/UNSW_NB15_testing-set.csv"
      description: "UNSW-NB15 dataset"
```

### **Step 4: Train Your Model**
```bash
# Train with sample data
python3 scripts/training/train_enhanced_ai.py

# Or train with specific dataset
python3 scripts/training/train_enhanced_ai.py --dataset nsl_kdd
```

## 💡 **Dataset Selection Tips**

### **For Beginners:**
- Start with **Sample Data** (already created)
- Then try **NSL-KDD** (small, clean, well-documented)

### **For Intermediate Users:**
- Use **UNSW-NB15** (comprehensive, modern attacks)
- Combine multiple datasets for better results

### **For Advanced Users:**
- Use **CICIDS2017/2018** (real-world, large scale)
- Consider **Bot-IoT** for IoT security
- Use **ToN_IoT** for industrial systems

### **For Production:**
- Use **CICIDS2018** (latest threats)
- Combine with **MITRE ATT&CK** data
- Add **VirusTotal** and **Shodan** data

## 🔧 **Data Preprocessing**

### **Feature Engineering**
```python
# Example preprocessing for NSL-KDD
import pandas as pd
from sklearn.preprocessing import LabelEncoder

# Load data
df = pd.read_csv('data/nsl_kdd/KDDTrain+.txt', header=None)

# Encode categorical features
le = LabelEncoder()
df[1] = le.fit_transform(df[1])  # protocol_type
df[2] = le.fit_transform(df[2])  # service
df[3] = le.fit_transform(df[3])  # flag
```

### **Data Validation**
```python
# Check data quality
print(f"Shape: {df.shape}")
print(f"Missing values: {df.isnull().sum().sum()}")
print(f"Unique labels: {df[41].unique()}")
```

## 📈 **Performance Expectations**

| Dataset | Expected Accuracy | Training Time | Memory Usage |
|---------|------------------|---------------|--------------|
| **Sample** | 85-90% | 1-2 minutes | 100MB |
| **NSL-KDD** | 90-95% | 5-10 minutes | 500MB |
| **UNSW-NB15** | 85-92% | 15-30 minutes | 1GB |
| **CICIDS2017** | 88-94% | 30-60 minutes | 2GB |
| **CICIDS2018** | 86-93% | 60-120 minutes | 4GB |

## 🚨 **Important Notes**

1. **Large datasets** require significant memory and time
2. **Start small** with sample data before scaling up
3. **Validate data** before training
4. **Backup models** after successful training
5. **Monitor performance** during training

## 📞 **Support**

If you have issues with datasets:

1. Check the official dataset websites
2. Verify file integrity with checksums
3. Ensure sufficient disk space
4. Check memory requirements
5. Use the sample data for testing first

---

**Happy Training! 🎉** 