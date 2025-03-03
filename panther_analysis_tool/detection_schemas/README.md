# Detection Schemas

This directory contains JSON Schema files that are automatically generated from Panther Analysis Tool's Python schema definitions. These schemas are used to validate the structure and content of various Panther analysis configurations.

## Schema Files

The following schema files are generated:

- `rule.json` - Schema for standard detection rules
- `correlation_rule.json` - Schema for correlation rules that analyze multiple events
- `policy.json` - Schema for resource policies
- `global.json` - Schema for global helper functions
- `pack.json` - Schema for analysis packs
- `saved_query.json` - Schema for saved queries
- `scheduled_query.json` - Schema for scheduled queries
- `lookup_table.json` - Schema for lookup tables
- `derived.json` - Schema for derived rules
- `data_model.json` - Schema for data models

## Generation

These files are automatically generated using the `bin/generate_schemas` script. The script converts Python schema definitions from `panther_analysis_tool.schemas` into JSON Schema format.

To regenerate these files:

```bash
./bin/generate_schemas
```

## Usage

These schema files are used internally by Panther Analysis Tool to:
- Validate analysis configurations before deployment
- Provide structure information for IDE integration
- Document the expected format of various analysis types

Do not modify these files directly as they are automatically generated. Instead, update the source schemas in `panther_analysis_tool/schemas.py`. 