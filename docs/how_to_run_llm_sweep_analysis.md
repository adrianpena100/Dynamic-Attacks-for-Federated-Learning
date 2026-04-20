# How to Run LLM Sweep Analysis

To run the LLM-based vulnerability analysis on a sweep (e.g., FEMNIST), use the following command from the `dynamic_fl` directory (with your virtual environment activated):

```sh
python scripts/llm_sweep_analysis.py --sweeps-root logs/sweeps/FEMNIST_2026-04-02 --call-api
```

- Replace `FEMNIST_2026-04-02` with the folder for your dataset/strategy.
- This will generate per-strategy and global markdown reports in the sweep folder.

## Steps
1. Activate your virtual environment:
   ```sh
   source ../myenv/bin/activate
   ```
2. Run the analysis command above.
3. View the results in the corresponding `llm_comprehensive_analysis.md` and `llm_global_analysis.md` files.

---

**Tip:**
You can preview markdown files in VS Code by right-clicking the file and selecting "Open Preview" or pressing `Cmd+Shift+V` (Mac) or `Ctrl+Shift+V` (Windows/Linux).
