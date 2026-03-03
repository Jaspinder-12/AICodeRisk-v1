# AICodeRisk-v1

Self-correcting and risk-aware AI coding project.

## Directory Structure

- `frontend/`: Web interface for code analysis.
- `backend/`: Python server and security engine.
- `docs/`: Critical documentation including CONTRACT.md.
- `project_v1.json`: Version V1 scope and constraints.

## Security & Setup

> [!IMPORTANT]
> **Never commit API keys to this repository.** This project is configured to use environment variables for security.

### Local Development
1. Create a `.env` file (ignored by git).
2. Add your key: `GOOGLE_API_KEY=your_key_here`
3. Restrict access to your `.env` file.

### Deployment (Render)
Go to your Dashboard -> Environment and add the `GOOGLE_API_KEY` environment variable.
