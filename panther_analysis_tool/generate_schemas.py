#!/usr/bin/env python3

"""
Script to generate JSON Schema files from Panther Analysis Tool's Python schemas.
This script converts the Python schema definitions to JSON Schema format.
"""

import os
import json
from typing import Any, Dict, List, Union
from schema import Schema, Or, And, Optional, Regex

from panther_analysis_tool.schemas import (
    RULE_SCHEMA,
    CORRELATION_RULE_SCHEMA,
    POLICY_SCHEMA,
    GLOBAL_SCHEMA,
    PACK_SCHEMA,
    SAVED_QUERY_SCHEMA,
    SCHEDULED_QUERY_SCHEMA,
    LOOKUP_TABLE_SCHEMA,
    DERIVED_SCHEMA,
    DATA_MODEL_SCHEMA,
)

def get_key_name(key: Any) -> str:
    """Get a string representation of a schema key."""
    if isinstance(key, str):
        return key
    elif isinstance(key, Optional):
        return str(key.schema)
    elif isinstance(key, Or):
        # For Or types in keys, use the first option as the key name
        return str(key.args[0])
    return str(key)

def schema_type_to_json(schema_type: Any) -> Dict[str, Any]:
    """Convert a schema type to JSON Schema format."""
    if isinstance(schema_type, str):
        return {"type": "string"}
    elif isinstance(schema_type, bool):
        return {"type": "boolean"}
    elif isinstance(schema_type, int):
        return {"type": "integer"}
    elif isinstance(schema_type, float):
        return {"type": "number"}
    elif isinstance(schema_type, list):
        return {"type": "array", "items": schema_type_to_json(schema_type[0]) if schema_type else {}}
    elif isinstance(schema_type, dict):
        return {
            "type": "object",
            "properties": {
                get_key_name(k): schema_type_to_json(v)
                for k, v in schema_type.items()
            }
        }
    elif isinstance(schema_type, Or):
        types = []
        for arg in schema_type.args:
            if isinstance(arg, str):
                types.append({"type": "string", "const": arg})
            else:
                types.append(schema_type_to_json(arg))
        return {"oneOf": types}
    elif isinstance(schema_type, And):
        return {"allOf": [schema_type_to_json(s) for s in schema_type.args]}
    elif isinstance(schema_type, Optional):
        return schema_type_to_json(schema_type.schema)
    elif isinstance(schema_type, Regex):
        return {"type": "string", "pattern": schema_type.pattern_str}
    elif isinstance(schema_type, Schema):
        if hasattr(schema_type, "schema"):
            return schema_type_to_json(schema_type.schema)
    return {"type": "string"}

def convert_schema_to_json(schema: Schema) -> Dict[str, Any]:
    """Convert a Python Schema object to JSON Schema format."""
    json_schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {},
        "required": [],
    }
    
    if hasattr(schema, "schema"):
        schema_dict = schema.schema
        for key, value in schema_dict.items():
            key_name = get_key_name(key)
            if not isinstance(key, Optional):
                json_schema["required"].append(key_name)
            json_schema["properties"][key_name] = schema_type_to_json(value)
    
    return json_schema

def main():
    """Generate JSON Schema files from Python schemas."""
    # Create schemas directory if it doesn't exist
    os.makedirs(".cursor/schemas", exist_ok=True)
    
    # Define schemas to convert
    schemas = {
        "rule": RULE_SCHEMA,
        "correlation_rule": CORRELATION_RULE_SCHEMA,
        "policy": POLICY_SCHEMA,
        "global": GLOBAL_SCHEMA,
        "pack": PACK_SCHEMA,
        "saved_query": SAVED_QUERY_SCHEMA,
        "scheduled_query": SCHEDULED_QUERY_SCHEMA,
        "lookup_table": LOOKUP_TABLE_SCHEMA,
        "derived": DERIVED_SCHEMA,
        "data_model": DATA_MODEL_SCHEMA,
    }
    
    # Generate JSON Schema files
    for name, schema in schemas.items():
        json_schema = convert_schema_to_json(schema)
        output_path = f".cursor/schemas/{name}.json"
        
        with open(output_path, "w") as f:
            json.dump(json_schema, f, indent=2)
        print(f"Generated {output_path}")

if __name__ == "__main__":
    main() 