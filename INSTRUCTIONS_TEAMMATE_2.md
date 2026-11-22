# 🧩 Teammate 2 Assignment: Online Drain Error Clustering

## Your Module
- `clustering.py`: Implements the online Drain-inspired prefix tree log clustering algorithm. Groups dynamic runtime errors into template signatures in O(1) time.
- `test_clustering.py`: Comprehensive test suite verifying token clustering and variable masking.

## How to add this to the project & push:

1. **Pull the latest code from GitHub:**
   ```bash
   git checkout main
   git pull origin main
   ```

2. **Create your feature branch:**
   ```bash
   git checkout -b feature/error-clustering
   ```

3. **Place your files:**
   - Copy `clustering.py` $\to$ `log_detective/clustering.py`
   - Copy `test_clustering.py` $\to$ `tests/test_clustering.py`

4. **Run tests to verify:**
   ```bash
   pytest -c pytest.ini tests/test_clustering.py
   ```

5. **Commit and push to GitHub:**
   ```bash
   git add log_detective/clustering.py tests/test_clustering.py
   git commit -m "feat: implement Drain online error clustering engine"
   git push -u origin feature/error-clustering
   ```

6. Open GitHub and create a Pull Request to merge into `main`!
