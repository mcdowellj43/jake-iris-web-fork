# DFIR-IRIS Module (DIM) Overview

This document provides context and implementation details for extending **DFIR-IRIS** with custom modules (DIMs).  
A DIM is a **Python package** that extends IRIS features. Modules are not long-running services — they are invoked only when triggered by user actions or predefined hooks.

---

## Module Types

DIMs fall into two categories:

### 1. Pipeline Modules
- Purpose: **Process evidence** through modular pipelines.  
- Example: Parsing EVTX logs and injecting results into IRIS.  
- Trigger: When a user selects evidence and runs **Update Case**.  

### 2. Processor Modules
- Purpose: **Process IRIS data** when specific actions/hooks occur.  
- Example: When a new IOC is created, enrich it with VirusTotal or MISP data.  
- Trigger: Automatically on specific events, or manually by users.  

> ⚙️ Both types run as **asynchronous RabbitMQ tasks**, ensuring UI performance is not impacted.

---

## Lifecycle and Execution

- Modules are **instantiated per action**. Initialization must be lightweight (avoid overriding `__init__` unless necessary).  
- Modules can run in the **worker**, the **web-app**, or both.  
- Multiple instances may run simultaneously.  
- IRIS handles **task creation and locking**; the module only needs to process data and return results.

---

## Module Structure

A typical module directory:

```
setup.py                # Build/configuration for the package
README.md               # Documentation for the module
iris_example_name/      # Module package
  __init__.py              # Declares the main module class
  IrisExampleConfig.py     # Configuration details
  IrisExampleInterface.py  # Main module class (inherits IrisModuleInterface)
  module_helper/           # Optional helpers
    helper.py
    helper2.py
```

### `__init__.py`
Required to declare the main class name:
```python
__iris_module_interface = "IrisEXAMPLEInterface"
```

This class must inherit from `IrisModuleInterface`.  
❌ If missing or incorrect → IRIS will fail to load the module.

---

## Module Configuration

Each module declares metadata and configuration options as class attributes.

### Required Attributes
- **_module_name**: Human-readable name for users.  
- **_interface_version**: Supported `IrisModuleInterface` version.  
- **_module_version**: Module’s own version number.  
- **_module_type**: Type of module (from `IrisModuleInterface.IrisModuleTypes`).  
- **_pipeline_support**: Boolean, set `True` for pipeline modules.  
- **_pipeline_info**: Dict describing pipeline configuration.  
- **_module_configuration**: List of dicts defining parameters exposed in the web UI.

### Example: `_pipeline_info`
```python
pipeline_info = {
    "pipeline_internal_name": "example_pipeline",   # Unique ID
    "pipeline_human_name": "Example Pipeline",      # Shown in UI
    "pipeline_args": [
        ["some_index", "required"],
        ["example_argument", "optional"]
    ]
}
```

### Example: `_module_configuration`
```python
_module_configuration = [
  {
    "param_name": "vt_api_key",
    "param_human_name": "VT API Key",
    "param_description": "VirusTotal API key",
    "default": None,
    "mandatory": True,
    "type": "sensitive_string"
  },
  {
    "param_name": "vt_key_is_premium",
    "param_human_name": "VT Key is premium",
    "param_description": "Set to True if the VT key is premium",
    "default": False,
    "mandatory": True,
    "type": "bool"
  },
  {
    "param_name": "vt_ip_assign_asn_as_tag",
    "param_human_name": "Assign ASN tag to IP",
    "param_description": "Assign ASN fetched from VT as a tag on IP IOCs",
    "default": True,
    "mandatory": True,
    "type": "bool"
  }
]
```

These fields appear in the IRIS module configuration page for user input.

---

## Key Takeaways

- DIMs let you extend IRIS by hooking into evidence ingestion (pipeline) or case/IOC events (processor).  
- Each DIM inherits from **IrisModuleInterface**, which provides the common framework.  
- DIMs run **asynchronously via RabbitMQ**, never blocking the UI.  
- Proper configuration in `__init__.py` and class attributes is essential for IRIS to register modules correctly.  
- Both **pipeline_info** and **module_configuration** enable customization and user-facing settings.

---

_Last updated from IRIS documentation: **2022-05-18**_
