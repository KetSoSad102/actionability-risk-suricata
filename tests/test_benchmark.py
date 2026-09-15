import tempfile
import unittest
from pathlib import Path
import subprocess
from as_engine.benchmark import measure

class BenchmarkTests(unittest.TestCase):
    def test_invalid_repeat_count_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                measure('as_engine.cli',[],d,repeats=0)

    def test_failed_child_is_not_reported_as_success(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(subprocess.CalledProcessError):
                measure('as_engine.module_that_does_not_exist',[],d,repeats=1,warmups=0)
            self.assertFalse((Path(d)/'benchmark.json').exists())
            self.assertIn('ImportError',(Path(d)/'run_0.log').read_text())

if __name__=='__main__':unittest.main()
