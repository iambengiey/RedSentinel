# ML-Driven SOAR Project

This project integrates Machine Learning into a SOAR stack built on top of SLES and RHEL systems running on ARM, x64, and XEN hypervisors.

## Structure

- `data/` - Raw logs and processed data from SLES/RHEL systems
- `models/` - Trained ML models (Pickle, ONNX)
- `notebooks/` - Jupyter notebooks for model training and experiments
- `scripts/` - ETL and inference scripts
- `ansible/` - Playbooks triggered by ML threat scoring
- `api/` - FastAPI app for real-time model inference
- `docs/` - Architecture diagrams and usage documentation

## First Steps

1. Place sample logs in `data/`
2. Use `notebooks/` to train a model
3. Export model to `models/`
4. Launch `api/` FastAPI server to serve predictions
5. Use Ansible playbooks from `ansible/` to automate response

