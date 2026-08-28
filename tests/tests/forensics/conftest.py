import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))          # repo/tests/forensics
ROOT = os.path.dirname(os.path.dirname(HERE))               # repo
sys.path.insert(0, os.path.join(ROOT, "member1-forensics"))
