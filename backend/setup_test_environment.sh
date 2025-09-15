#!/bin/bash

echo "🔧 Setting up comprehensive test environment..."

# Ensure we're in the backend directory
cd "$(dirname "$0")"

# Activate virtual environment
source venv/bin/activate || {
    echo "❌ Error: Could not activate virtual environment"
    echo "Please run: python -m venv venv"
    exit 1
}

echo "✅ Virtual environment activated"

# Install system dependencies (macOS)
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "🍺 Installing system dependencies with Homebrew..."
    brew install libomp 2>/dev/null || echo "ℹ️  libomp already installed or Homebrew not available"
fi

echo "📦 Installing Python dependencies..."

# Core dependencies
pip install --upgrade pip

echo "📋 Installing from comprehensive requirements..."
# Install comprehensive requirements
if [ -f "requirements-comprehensive.txt" ]; then
    pip install -r requirements-comprehensive.txt
    echo "✅ Installed comprehensive requirements"
else
    echo "⚠️  requirements-comprehensive.txt not found, installing individual packages..."
    # Fallback to individual installation
    pip install fastapi uvicorn sqlalchemy asyncpg temporalio pytest numpy tensorflow torch transformers scikit-learn
fi

echo "🧩 Installing additional compatibility packages..."
pip install tf-keras  # For TensorFlow compatibility

# Download spacy model
python -m spacy download en_core_web_sm 2>/dev/null || echo "ℹ️  Spacy model download skipped"

echo "🧪 Testing import capabilities..."

# Test critical imports
python -c "
import sys
failed_imports = []

test_imports = [
    'fastapi', 'uvicorn', 'sqlalchemy', 'asyncpg', 'temporalio',
    'pydantic', 'numpy', 'pandas', 'sklearn', 'matplotlib',
    'tensorflow', 'torch', 'transformers', 'xgboost',
    'pytest', 'redis'
]

for module in test_imports:
    try:
        __import__(module)
        print(f'✅ {module}')
    except ImportError as e:
        print(f'❌ {module}: {e}')
        failed_imports.append(module)

if failed_imports:
    print(f'\n⚠️  Failed to import: {failed_imports}')
    print('Some tests may not run. This is usually due to system dependencies.')
else:
    print('\n🎉 All critical dependencies imported successfully!')
"

echo ""
echo "🏁 Test environment setup complete!"
echo ""
echo "📋 Next steps:"
echo "1. Run all tests: source venv/bin/activate && PYTHONPATH=. python -m pytest tests/ -v"
echo "2. Run core tests: source venv/bin/activate && PYTHONPATH=. python -m pytest tests/test_pkce_implementation.py tests/test_simple.py tests/test_config.py -v"
echo "3. Run Temporal demo: source venv/bin/activate && PYTHONPATH=. python simple_temporal_test.py"